package ddns

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSparseOversizedState creates a SPARSE ownership file whose reported size
// exceeds maxDDNSStateBytes without allocating that many real bytes: f.Truncate
// extends the file with zero bytes that most filesystems (tmpfs/ext4 under
// t.TempDir) keep unbacked. loadDDNSState's os.Stat pre-check must reject it by
// SIZE before ever reading it — so this test costs a stat, not a 128 MiB read,
// on the FIXED path. (Only a REVERT that restores the unbounded os.ReadFile would
// pull the whole sparse file into memory, which is the vulnerability #5571 fixes.)
func writeSparseOversizedState(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create sparse state: %v", err)
	}
	if err := f.Truncate(maxDDNSStateBytes + 1); err != nil {
		f.Close()
		t.Fatalf("truncate sparse state: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close sparse state: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != maxDDNSStateBytes+1 {
		t.Fatalf("sparse state size = %v (err %v), want %d", fi, err, maxDDNSStateBytes+1)
	}
}

// TestLoadDDNSStateRejectsOversizedFile is the #5571 (CWE-770) fail-on-revert
// test: an ownership file larger than maxDDNSStateBytes must be REFUSED by the
// size bound BEFORE it is buffered whole, and classified fail-closed corrupt so
// the manager quarantines it and degrades rather than OOMing at startup.
//
// RED on revert: restore the unbounded `data, err := os.ReadFile(path)` (drop
// readBoundedStateFile and the errDDNSStateCorrupt branch) and the whole sparse
// file is read into memory; json.Unmarshal then fails, so the load is classified
// errDDNSStateCorrupt but NOT errDDNSStateTooLarge — the errDDNSStateTooLarge
// assertion below fails, proving the read was no longer bounded by size.
func TestLoadDDNSStateRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	writeSparseOversizedState(t, path)

	s, err := loadDDNSState(path)
	if err == nil {
		t.Fatal("loadDDNSState accepted an oversized file; want a size-bound error")
	}
	// The over-bound file is refused by the SIZE bound (not by a downstream JSON
	// parse error after a full read) — this is what distinguishes bounded from
	// unbounded and gives the RED on revert.
	if !errors.Is(err, errDDNSStateTooLarge) {
		t.Fatalf("oversized file not refused by the size bound (errDDNSStateTooLarge): %v", err)
	}
	// It engages the SAME fail-closed classification as an unparseable/bad-version
	// store, so loadStateOrDegrade quarantines it and marks the manager degraded.
	if !errors.Is(err, errDDNSStateCorrupt) {
		t.Fatalf("oversized error must wrap errDDNSStateCorrupt (fail-closed), got %v", err)
	}
	if s == nil || len(s.records) != 0 {
		t.Fatalf("oversized load must return an empty store, got %+v", s)
	}
}

// TestLoadStateOrDegradeOversizedFileFailsClosed proves the oversized file drives
// the SAME startup fail-closed posture the loader uses for a corrupt file: the
// manager is degraded, the bad file is quarantined aside (renamed to
// <path>.corrupt-<stamp>, preserved for inspection), and a durable <path>.degraded
// marker is written so a restart does not silently resume with ownership
// forgotten. RED on revert: an unbounded read reads+parses the sparse zeros, which
// is still corrupt, so degrade+quarantine still fire — but the loadDDNSState test
// above is the load-bearing RED. This test pins the end-to-end posture.
func TestLoadStateOrDegradeOversizedFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	writeSparseOversizedState(t, path)

	fixed := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	st, degraded, reason := loadStateOrDegrade(path, func() time.Time { return fixed })
	if !degraded {
		t.Fatal("oversized ownership file must put the manager into the degraded (fail-closed) state")
	}
	if reason == "" {
		t.Fatal("degraded reason must be populated for an oversized file")
	}
	if st == nil || len(st.records) != 0 {
		t.Fatalf("oversized load must yield an empty store, got %+v", st)
	}
	// The oversized file is quarantined (renamed away), not left in place.
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized file was not quarantined (still present at %s): %v", path, err)
	}
	stamp := fixed.UTC().Format("20060102T150405Z")
	quarantined := path + ".corrupt-" + stamp
	if _, err := os.Stat(quarantined); err != nil {
		t.Fatalf("quarantined copy missing at %s: %v", quarantined, err)
	}
	// A durable degraded marker keeps the fail-closed posture across restart.
	if _, err := os.Stat(path + degradedMarkerSuffix); err != nil {
		t.Fatalf("durable degraded marker missing: %v", err)
	}
}

// TestLoadDDNSStateAcceptsNormalSizedFile guards against a false positive: a
// well-formed, normal-sized store must still load cleanly under the bound.
func TestLoadDDNSStateAcceptsNormalSizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	good := `{"version":1,"records":[{"family":4,"identity":"mac:aa","address":"203.0.113.5",` +
		`"fqdn":"host.example.net","forward_type":"A","ptr_name":"5.113.0.203.in-addr.arpa","ttl":300}]}`
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatalf("write good state: %v", err)
	}
	s, err := loadDDNSState(path)
	if err != nil {
		t.Fatalf("loadDDNSState rejected a valid normal-sized store: %v", err)
	}
	if len(s.records) != 1 {
		t.Fatalf("valid store: want 1 record, got %d", len(s.records))
	}
}

// TestReadBoundedStateFileMissingIsNotExist pins that a missing file returns an
// os.ErrNotExist-classified error (so loadDDNSState treats first boot as a clean
// empty store, not a corrupt one).
func TestReadBoundedStateFileMissingIsNotExist(t *testing.T) {
	_, err := readBoundedStateFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file must classify as os.ErrNotExist, got %v", err)
	}
}
