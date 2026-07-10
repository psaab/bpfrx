package dhcp

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// firstRealIface returns the name of a usable local interface for DUID
// generation, skipping the test if none is available.
func firstRealIface(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skipf("no interfaces available: %v", err)
	}
	return ifaces[0].Name
}

// TestClearAllDUIDsRemovesPersistedAndSurfacesErrors pins #4909: ClearAllDUIDs
// must clear DUIDs persisted on disk (including one whose client has not called
// getDUID since restart, so it is absent from the in-memory cache) and must
// surface delete errors instead of reporting "all cleared".
//
// RED on revert: the pre-fix ClearAllDUIDs iterated only m.duids and returned
// nothing — the on-disk "ghost" DUID below survives (first assertion fails) and
// there is no error channel for the delete failure (the signature change alone
// fails to compile).
func TestClearAllDUIDsRemovesPersistedAndSurfacesErrors(t *testing.T) {
	stateDir := t.TempDir()
	m := &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{},
		stateDir:  stateDir,
	}

	// A persisted DUID with no in-memory cache entry (client never re-fetched
	// since restart). Only the on-disk file exists.
	ghost := filepath.Join(stateDir, "dhcpv6-duid-ge-0-0-9")
	if err := os.WriteFile(ghost, []byte("duid-bytes"), 0o644); err != nil {
		t.Fatalf("seed ghost DUID: %v", err)
	}

	if err := m.ClearAllDUIDs(); err != nil {
		t.Fatalf("ClearAllDUIDs: %v", err)
	}
	if _, err := os.Stat(ghost); !os.IsNotExist(err) {
		t.Fatalf("persisted DUID untouched by ClearAllDUIDs (stat err=%v)", err)
	}

	// A cached-but-unclearable interface (invalid name → duidPath rejects it)
	// must surface an aggregated error, not be swallowed.
	m2 := &Manager{
		duids:     map[string]dhcpv6.DUID{"../../evil": nil},
		duidTypes: map[string]string{},
		stateDir:  stateDir,
	}
	if err := m2.ClearAllDUIDs(); err == nil {
		t.Fatal("ClearAllDUIDs swallowed a delete error; want a surfaced error")
	}
}

// TestGetDUIDLLTSurfacesPersistFailure pins #4909: a DUID-LLT that cannot be
// persisted is EPHEMERAL (the embedded timestamp changes on restart), so
// getDUID must surface the persist failure instead of silently handing out an
// unstable identity. A DUID-LL is a pure function of the hardware address and
// stays benign on persist failure (logged, not fatal).
//
// RED on revert: the pre-fix getDUID only logged a Warn on persist failure and
// returned the ephemeral DUID with a nil error — the LLT assertion (want error)
// fails.
func TestGetDUIDLLTSurfacesPersistFailure(t *testing.T) {
	ifName := firstRealIface(t)

	tmp := t.TempDir()
	// A regular file where the state dir should be: saveDUID's MkdirAllDurable
	// fails with ENOTDIR, so persistence is guaranteed to fail.
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	unwritable := filepath.Join(blocker, "state")

	llt := &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{ifName: "duid-llt"},
		stateDir:  unwritable,
	}
	if _, err := llt.getDUID(ifName); err == nil {
		t.Fatal("getDUID for a DUID-LLT with a failing persist returned nil error; " +
			"want the persist failure surfaced (ephemeral DUID otherwise)")
	}

	// The same persist failure for a DUID-LL is tolerated: it is deterministic
	// from the MAC and byte-identical across restart.
	ll := &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{ifName: "duid-ll"},
		stateDir:  unwritable,
	}
	if _, err := ll.getDUID(ifName); err != nil {
		t.Fatalf("getDUID for a DUID-LL should tolerate a persist failure, got: %v", err)
	}
}
