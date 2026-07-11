package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5493: deprovisionLoginUser must fail CLOSED on a transient /etc/passwd read
// error. lookupUID/lookupUIDGID map ANY os.ReadFile(passwdPath) failure to
// ok=false, so before the fix a mount/permission/I/O hiccup reading the
// identity database was indistinguishable from a genuine out-of-band userdel.
// The caller then dropped the ONLY provenance marker and returned before
// locking the shadow password or removing managed authorized_keys — and once
// passwd was readable again the account was no longer enumerated (marker gone),
// so revocation was PERMANENTLY abandoned: a removed user's password and keys
// stayed active forever. The asymmetry the fix restores: a /etc/shadow read
// error already fails closed ("keep marker, retry"); a /etc/passwd read error
// must too. Only a *readable* passwd that lacks the name is the real deletion
// that legitimately drops the marker.

// forceUnreadable points a *Path package var at a directory so os.ReadFile
// fails with EISDIR deterministically regardless of euid (a chmod 0000 would be
// bypassed when the test runs as root). The stageDeprovisionEnv cleanup restores
// the original path.
func forceUnreadable(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestDeprovisionPasswdReadErrorFailsClosed is the #5493 fail-on-revert guard:
// a passwd READ error during deprovision must be a no-op that RETAINS the
// marker (revocation intent) for the next apply — it must NOT lock the shadow
// password, remove authorized_keys, or drop the marker. Reverting the fix (the
// old `curUID, uidOK := lookupUID(name); if !uidOK { os.Remove(markerPath); return }`
// bool contract) makes assertion (c) RED: the marker is deleted and revocation
// is permanently abandoned (fail-open).
func TestDeprovisionPasswdReadErrorFailsClosed(t *testing.T) {
	sentinel := stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\ndave:x:1001:1001:,,,:/home/dave:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\ndave:$6$salt$activehash:19000:0:99999:7:::\n",
	)

	// dave was provisioned at UID 1001 (matches passwd) and has managed keys.
	if err := markProvisioned("dave", 1001); err != nil {
		t.Fatal(err)
	}
	keysFile := managedAuthorizedKeysPath("dave")
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA dave@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Force a transient /etc/passwd read failure (identity DB unavailable).
	passwdPath = forceUnreadable(t, "passwd-is-a-dir")

	// dave removed from config entirely.
	d := &Daemon{}
	d.reconcileAbsentLoginUsers(&config.Config{})

	// (a) chpasswd was NOT invoked — the shadow password is not locked.
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran despite a passwd read error (err=%v) — must fail closed", err)
	}
	// (b) the managed authorized_keys is UNTOUCHED (key login not revoked yet).
	if _, err := os.Stat(keysFile); err != nil {
		t.Fatalf("authorized_keys removed despite a passwd read error: %v", err)
	}
	// (c) the provenance marker is RETAINED so the next apply retries. Dropping
	// it here permanently abandons revocation (#5493, the fail-open bug).
	if _, err := os.Stat(markerPath("dave")); err != nil {
		t.Fatalf("provenance marker dropped on a passwd read error — revocation permanently abandoned (#5493): %v", err)
	}
}

// TestDeprovisionGenuineAbsenceDropsMarker proves the genuine-deletion path is
// UNCHANGED: when passwd is READABLE and simply does not contain the name (a
// real out-of-band userdel), there is nothing to revoke and the stale marker is
// dropped so xpf stops revisiting it. This is the behavior the read-error path
// must NOT be confused with.
func TestDeprovisionGenuineAbsenceDropsMarker(t *testing.T) {
	sentinel := stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\n", // passwd readable, "gone" absent
		"root:$6$r$h:19000:0:99999:7:::\n",
	)

	// "gone" has a provenance marker but no live account.
	if err := markProvisioned("gone", 1001); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	d.reconcileAbsentLoginUsers(&config.Config{})

	// Nothing to revoke: chpasswd never runs, and the marker is dropped.
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran for an already-absent account (err=%v)", err)
	}
	if _, err := os.Stat(markerPath("gone")); !os.IsNotExist(err) {
		t.Fatalf("marker retained for a genuinely-absent account — it should be dropped (err=%v)", err)
	}
}

// TestDeprovisionShadowReadErrorFailsClosed pins the pre-existing #1944 shadow
// fail-closed contract that the passwd fix mirrors: passwd is readable and
// contains the (provisioned) user, so the account is FOUND, but /etc/shadow
// cannot be read. The deprovision must retain the marker and keys and must not
// lock — a read hiccup can never revoke, and never abandon revocation.
func TestDeprovisionShadowReadErrorFailsClosed(t *testing.T) {
	sentinel := stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nheidi:x:1001:1001:,,,:/home/heidi:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\nheidi:$6$salt$hash:19000:0:99999:7:::\n",
	)

	if err := markProvisioned("heidi", 1001); err != nil {
		t.Fatal(err)
	}
	keysFile := managedAuthorizedKeysPath("heidi")
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA heidi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// passwd stays readable (heidi FOUND); only /etc/shadow fails to read.
	shadowPath = forceUnreadable(t, "shadow-is-a-dir")

	d := &Daemon{}
	d.reconcileAbsentLoginUsers(&config.Config{})

	// Fail-closed: no lock, keys retained, marker retained.
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("chpasswd ran despite a shadow read error (err=%v)", err)
	}
	if _, err := os.Stat(keysFile); err != nil {
		t.Fatalf("authorized_keys removed despite a shadow read error: %v", err)
	}
	if _, err := os.Stat(markerPath("heidi")); err != nil {
		t.Fatalf("marker dropped despite a shadow read error — must be retained: %v", err)
	}
}

// TestLookupUIDGIDErrThreeState unit-checks the new 3-state helper directly: a
// found user, a readable-but-absent user (found=false, err=nil), and an
// unreadable passwd (found=false, err!=nil). The err return is the exact signal
// deprovisionLoginUser uses to distinguish "unknown → retry" from "absent →
// forget".
func TestLookupUIDGIDErrThreeState(t *testing.T) {
	stageDeprovisionEnv(t,
		"root:x:0:0:root:/root:/bin/bash\nivan:x:1234:1234:,,,:/home/ivan:/bin/bash\n",
		"root:$6$r$h:19000:0:99999:7:::\n",
	)

	// Found.
	if uid, gid, found, err := lookupUIDGIDErr("ivan"); !found || err != nil || uid != 1234 || gid != 1234 {
		t.Fatalf("lookupUIDGIDErr(ivan) = (%d,%d,%v,%v), want (1234,1234,true,nil)", uid, gid, found, err)
	}
	// Readable passwd, name absent → genuine absence (no error).
	if _, _, found, err := lookupUIDGIDErr("nobody"); found || err != nil {
		t.Fatalf("lookupUIDGIDErr(nobody) = (found=%v,err=%v), want (false,nil) for a readable-but-absent name", found, err)
	}
	// Unreadable passwd → read error (unknown), NOT genuine absence.
	passwdPath = forceUnreadable(t, "passwd-is-a-dir")
	if _, _, found, err := lookupUIDGIDErr("ivan"); found || err == nil {
		t.Fatalf("lookupUIDGIDErr on unreadable passwd = (found=%v,err=%v), want (false,non-nil)", found, err)
	}
	// The two-state lookupUID wrapper still collapses a read error to ok=false
	// (unchanged contract for skip-and-retry callers).
	if _, ok := lookupUID("ivan"); ok {
		t.Fatal("lookupUID on unreadable passwd returned ok=true; want false (unchanged bool contract)")
	}
}
