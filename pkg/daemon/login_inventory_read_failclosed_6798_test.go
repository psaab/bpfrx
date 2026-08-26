package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6798: credential revocation treated an UNREADABLE ownership inventory as an
// EMPTY or UNOWNED one.
//
// Every marker read (os.ReadFile) and every inventory enumeration (os.ReadDir)
// collapsed its error into the same value a genuine ABSENCE produces — `false`
// for a marker, an empty slice for a root, a discarded error for sudoers.d.
// Absence is a determination ("this credential is not xpf's, skip it");
// unreadability proves nothing. Because both spellings arrived as the same
// value, every revocation gate read "could not tell" as "not ours" and
// SKIPPED, then returned nil — reporting convergence — while a removed or
// demoted administrator's password, authorized_keys, or passwordless sudo
// grant stayed live on disk. The #5874 cancellation closeout, which exists to
// observe exactly this monotonic-revocation gap, saw nothing to report.
//
// The invariant these guards pin: only PROVEN ABSENCE may release ownership
// work. Unknown ownership retains the debt (markers stay, an error is
// returned) and never converges. It equally must not REVOKE on unproven
// ownership — acting on a marker xpf cannot read is #6797's overclaim from the
// other side, and for root's authorized_keys it is a total lockout. So each
// gate below asserts BOTH halves: the credential is untouched AND the error is
// reported.
//
// Each test is named for the one production line it pins; reverting that line
// alone must turn the named cell RED.

// unreadableMarkerPath makes one marker path UNREADABLE without depending on
// file permissions: it replaces the marker with a DIRECTORY, so os.ReadFile
// opens it and then fails the read with EISDIR.
//
// Permission bits are the obvious lever and the wrong one — the suite may run
// as root, where chmod 000 is bypassed and the fixture would silently become a
// readable marker, i.e. a false green. EISDIR is uid-independent.
func unreadableMarkerPath(t *testing.T, dir, name string) string {
	t.Helper()
	path := markerPathIn(dir, name)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	// Prove the fixture actually produces a read ERROR and not an absence,
	// otherwise every assertion built on it is vacuous.
	if _, err := os.ReadFile(path); err == nil {
		t.Fatalf("fixture is inert: %s reads cleanly, so no gate under test "+
			"can enter its unreadable branch", path)
	} else if os.IsNotExist(err) {
		t.Fatalf("fixture produced ABSENCE, not unreadability, at %s: %v", path, err)
	}
	return path
}

// unreadableRootDir makes one inventory ROOT unreadable by replacing the
// directory with a regular FILE, so os.ReadDir fails with ENOTDIR. Like
// unreadableMarkerPath this is uid-independent — root can read a 000 dir.
func unreadableRootDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadDir(dir); err == nil {
		t.Fatalf("fixture is inert: ReadDir(%s) succeeded", dir)
	} else if os.IsNotExist(err) {
		t.Fatalf("fixture produced ABSENCE, not unreadability, at %s: %v", dir, err)
	}
}

// TestReadProvenanceMarkerSeparatesAbsentFromUnreadable_6798 pins the
// ENOENT-vs-other split in readProvenanceMarker.
//
// This is the root of the defect: the reader returned a bare bool, so ENOENT
// (a determination) and EISDIR/EACCES/EIO (not a determination) were the same
// `false`.
//
// FAIL-ON-REVERT: restore `if err != nil { return false }` in
// readProvenanceMarker (dropping the os.IsNotExist split) and the UNREADABLE
// row goes RED — err becomes nil, so "could not tell" reads as "proven not
// ours" again. The ABSENT row is the paired control: it pins err == nil, so
// the opposite mutation (returning an error unconditionally) also REDS. A
// guard with only the unreadable row would be satisfied by a reader that
// errored on everything, which would brick every fresh install.
func TestReadProvenanceMarkerSeparatesAbsentFromUnreadable_6798(t *testing.T) {
	dir := t.TempDir()

	// ABSENT: a determination. Not ours, no error.
	owned, err := readProvenanceMarker(dir, "absent", 1001)
	if owned || err != nil {
		t.Errorf("absent marker = (%v, %v), want (false, nil): a marker that is "+
			"genuinely missing PROVES the credential is not xpf's, and must not "+
			"be reported as a read failure — every fresh install has no markers",
			owned, err)
	}

	// PRESENT and matching: a determination. Ours, no error.
	if err := writeProvenanceMarker(dir, "mine", 1002); err != nil {
		t.Fatal(err)
	}
	owned, err = readProvenanceMarker(dir, "mine", 1002)
	if !owned || err != nil {
		t.Errorf("matching marker = (%v, %v), want (true, nil)", owned, err)
	}

	// UNREADABLE: NOT a determination. Ownership stays false (never revoke on
	// an unproven claim) but the error must surface.
	unreadableMarkerPath(t, dir, "opaque")
	owned, err = readProvenanceMarker(dir, "opaque", 1003)
	if err == nil {
		t.Error("an UNREADABLE marker reported no error, so it is indistinguishable " +
			"from a genuinely absent one. Every revocation gate reads that as " +
			"\"not ours, skip\" and then reports convergence, leaving the " +
			"credential live (#6798)")
	}
	if owned {
		t.Error("an UNREADABLE marker reported OWNERSHIP; xpf would revoke a " +
			"credential it cannot prove it owns (#6797 overclaim)")
	}
}

// TestClaimOwnershipTreatsUnreadableMarkerAsPreExisting_6798 pins the
// claimOwnership fail-closed default.
//
// preExisting gates exactly one thing: rollback(), which REMOVES the marker.
// Removing a marker RELEASES ownership, and only proven absence may do that.
// If the marker cannot be read, xpf cannot prove it did not already own the
// credential, and withdrawing a real marker orphans a live credential xpf can
// then never lock or revoke — the #5841 underclaim.
//
// FAIL-ON-REVERT: drop the `owned = true` assignment in claimOwnership's
// readErr branch and this REDS — preExisting becomes false and rollback()
// would withdraw a claim that may be genuine.
func TestClaimOwnershipTreatsUnreadableMarkerAsPreExisting_6798(t *testing.T) {
	dir := t.TempDir()
	path := unreadableMarkerPath(t, dir, "opaque")

	// The marker write also fails here (rename over a directory); that is
	// incidental. What is under test is the ownership READ that precedes it.
	c, _ := claimOwnership(dir, "opaque", 1004)
	if !c.preExisting {
		t.Fatal("claimOwnership over an UNREADABLE marker reported preExisting=false, " +
			"which makes rollback() WITHDRAW the marker. xpf cannot prove it did " +
			"not already own this credential, and withdrawing a genuine claim " +
			"orphans a live credential it can never revoke (#5841 underclaim, #6798)")
	}

	// The consequence: rollback must be inert in this state.
	c.rollback()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rollback removed a marker whose ownership could not be read: %v", err)
	}
}

// TestProvisionedNamesReportsUnreadableRoot_6798 pins the ReadDir error split
// in provisionedNames.
//
// FAIL-ON-REVERT: restore the bare `continue` (dropping the
// `if !os.IsNotExist(err)` accumulation) and the UNREADABLE subtest REDS.
// The ABSENT subtest is the paired control that keeps the fix from degenerating
// into "always error": all three roots missing is a fresh install and MUST stay
// a clean nil.
func TestProvisionedNamesReportsUnreadableRoot_6798(t *testing.T) {
	t.Run("all roots absent is a clean determination", func(t *testing.T) {
		dir := t.TempDir()
		orig := provisionedUsersDir
		provisionedUsersDir = filepath.Join(dir, "provisioned-users")
		t.Cleanup(func() { provisionedUsersDir = orig })

		names, err := provisionedNames()
		if err != nil {
			t.Errorf("provisionedNames with no roots at all = %v, want nil: a "+
				"fresh install has provisioned nothing, which is a "+
				"determination, not a read failure", err)
		}
		if len(names) != 0 {
			t.Errorf("provisionedNames = %v, want empty", names)
		}
	})

	t.Run("unreadable root is reported and does not truncate the sweep", func(t *testing.T) {
		dir := t.TempDir()
		orig := provisionedUsersDir
		provisionedUsersDir = filepath.Join(dir, "provisioned-users")
		t.Cleanup(func() { provisionedUsersDir = orig })

		// A readable root that DOES name an account...
		if err := markPasswordProvisioned("readable", 1005); err != nil {
			t.Fatal(err)
		}
		// ...and an unreadable one beside it.
		unreadableRootDir(t, provisionedKeysDir())

		names, err := provisionedNames()
		if err == nil {
			t.Error("an UNREADABLE ownership root contributed no names AND no error, " +
				"so the inventory looks complete when it is truncated. Accounts " +
				"whose only marker lived there are silently never revoked (#6798)")
		}
		// Revoking what we CAN see is strictly better than revoking nothing:
		// the error carries the debt, it must not discard the readable half.
		if _, ok := names["readable"]; !ok {
			t.Errorf("names = %v, want it to still contain \"readable\": an "+
				"unreadable root must not suppress the roots that DID read", names)
		}
	})
}

// stageRemovedUserEnv stages a removed login user who still has a live
// password and a live authorized_keys on disk, with all three ownership marker
// roots relocated under a temp dir. It returns the user's managed
// authorized_keys path.
func stageRemovedUserEnv(t *testing.T, name string, uid int) string {
	t.Helper()
	dir := t.TempDir()

	shadow := filepath.Join(dir, "shadow")
	// A USABLE hash, deliberately: the removed user's password is live, which
	// is the credential the deprovision is supposed to lock.
	shadowContent := fmt.Sprintf(
		"root:*:19000:0:99999:7:::\n%s:$6$salt$livehash:19000:0:99999:7:::\n", name)
	if err := os.WriteFile(shadow, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	passwdContent := fmt.Sprintf(
		"root:x:0:0:root:/root:/bin/bash\n%s:x:%d:%d:,,,:/home/%s:/bin/bash\n",
		name, uid, uid, name)
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o600); err != nil {
		t.Fatal(err)
	}

	origShadow, origPasswd, origDir, origHome := shadowPath, passwdPath, provisionedUsersDir, homeBaseDir
	shadowPath, passwdPath = shadow, passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = origShadow, origPasswd, origDir, origHome
	})

	keysFile := managedAuthorizedKeysPath(name)
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA "+name+"-live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return keysFile
}

// TestDeprovisionUnreadableOwnershipDoesNotConverge_6798 pins the ownErr gate
// in deprovisionLoginUser — the highest-consequence site.
//
// Before the fix, all three marker reads failing produced three falses, which
// matched the "nothing xpf-owned, never touch an out-of-band account" branch
// and returned nil. That nil is the whole defect: a removed administrator kept
// their password and SSH keys while the reconcile reported success.
//
// FAIL-ON-REVERT: drop the `if ownErr != nil { ... return retErr }` block and
// this REDS on the error assertion — the function returns nil for a removed
// user whose credentials are demonstrably still live.
func TestDeprovisionUnreadableOwnershipDoesNotConverge_6798(t *testing.T) {
	keysFile := stageRemovedUserEnv(t, "mallory", 1006)

	// All three ownership markers are unreadable: xpf cannot tell whether it
	// provisioned mallory's credentials.
	unreadableMarkerPath(t, provisionedUsersDir, "mallory")
	unreadableMarkerPath(t, provisionedPasswordsDir(), "mallory")
	unreadableMarkerPath(t, provisionedKeysDir(), "mallory")

	d := &Daemon{}
	err := d.deprovisionLoginUser("mallory")

	if err == nil {
		t.Fatal("deprovisionLoginUser reported SUCCESS for a removed user whose " +
			"ownership markers could not be read. Its password and authorized_keys " +
			"are still live, but the #5874 closeout sees convergence and lets " +
			"shutdown/HA promotion proceed — the removed admin keeps host access (#6798)")
	}
	if !strings.Contains(err.Error(), "determine ownership for removed user mallory") {
		t.Errorf("error = %v, want it to name the ownership-determination failure "+
			"for mallory; a different error would mean this cell is green for the "+
			"wrong reason", err)
	}

	// Never revoke on unproven ownership: the key file may be the operator's own.
	if _, statErr := os.Stat(keysFile); statErr != nil {
		t.Errorf("authorized_keys was REMOVED on unreadable ownership (%v); xpf "+
			"revoked a credential it cannot prove it owns (#6797 overclaim)", statErr)
	}
	// Retry debt is retained: the markers must survive so the next apply retries.
	for _, dir := range []string{provisionedUsersDir, provisionedPasswordsDir(), provisionedKeysDir()} {
		if _, statErr := os.Stat(markerPathIn(dir, "mallory")); statErr != nil {
			t.Errorf("ownership marker under %s was dropped on an unreadable read "+
				"(%v); once the root is readable again mallory is no longer "+
				"enumerated, so revocation is abandoned PERMANENTLY", dir, statErr)
		}
	}
}

// TestReconcileAbsentLoginUsersReportsUnreadableInventory_6798 pins the invErr
// propagation in reconcileAbsentLoginUsers.
//
// The reverted form read `names := provisionedNames(); if len(names) == 0 {
// return nil }`, so an inventory that was entirely unreadable produced an empty
// set and an immediate SUCCESS. The fixture therefore keeps the readable roots
// ABSENT so the name set really is empty — that is the exact shape the old
// early return converged on. A fixture with any readable name would not enter
// it and would be a false green.
//
// FAIL-ON-REVERT: drop the `if invErr != nil { retErr = errors.Join(...) }`
// block and this REDS.
func TestReconcileAbsentLoginUsersReportsUnreadableInventory_6798(t *testing.T) {
	dir := t.TempDir()
	orig := provisionedUsersDir
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { provisionedUsersDir = orig })

	// The keys root is unreadable; the other two are genuinely absent, so the
	// readable half of the inventory names NOTHING.
	unreadableRootDir(t, provisionedKeysDir())

	d := &Daemon{}
	err := d.reconcileAbsentLoginUsers(loginCfg())

	if err == nil {
		t.Fatal("reconcileAbsentLoginUsers reported SUCCESS over an inventory it " +
			"could not read. An unreadable root yields no names, which the old " +
			"len(names)==0 early return treated as \"nothing was ever " +
			"provisioned, nothing to revoke\" — indistinguishable from a fresh " +
			"install, and the removed users it should have swept keep their " +
			"credentials (#6798)")
	}
	if !strings.Contains(err.Error(), "read ownership inventory") {
		t.Errorf("error = %v, want it to name the unreadable inventory root", err)
	}
}

// TestEmptiedKeyListUnreadableMarkerDoesNotConverge_6798 pins the ownErr gate
// in applySystemLogin's emptied-key-list branch.
//
// FAIL-ON-REVERT: drop the `if ownErr != nil { fail(...) }` block in
// applySystemLogin and this REDS — ownsKeys stays false, the revoke branch is
// skipped, and the apply reports convergence for a key list that was never
// honoured.
func TestEmptiedKeyListUnreadableMarkerDoesNotConverge_6798(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "nora", 1007)

	// The key file is live on disk but xpf cannot read its ownership marker.
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA nora-live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadableMarkerPath(t, provisionedKeysDir(), "nora")

	// nora is RETAINED in config but her key list is now empty.
	d := &Daemon{}
	err := d.applySystemLogin(loginCfg(&config.LoginUser{Name: "nora", Class: "operator"}))

	if err == nil {
		t.Fatal("applySystemLogin reported SUCCESS after emptying a key list whose " +
			"ownership marker could not be read. The key file is still on disk, so " +
			"key-based login is NOT revoked, yet the apply converged (#6798)")
	}
	if !strings.Contains(err.Error(), "determine key ownership for nora") {
		t.Errorf("error = %v, want it to name the key-ownership determination "+
			"failure for nora; any other error means this cell is green for the "+
			"wrong reason", err)
	}
	// And it must NOT have revoked on the unproven claim.
	if _, statErr := os.Stat(keysFile); statErr != nil {
		t.Errorf("authorized_keys removed on unreadable ownership (%v) — that is "+
			"the #6797 overclaim: the file may be the operator's own", statErr)
	}
}

// TestPasswordLockUnreadableMarkerDoesNotConverge_6798 pins the ownErr gate in
// reconcileUserPassword's pwLock branch.
//
// FAIL-ON-REVERT: drop the `if ownErr != nil { fail(...); break }` block and
// this REDS — the `!uidOK || !ownsPassword` test below it swallows the
// unreadable marker as "not ours" and breaks silently, reporting convergence
// for a declarative lock that never happened.
func TestPasswordLockUnreadableMarkerDoesNotConverge_6798(t *testing.T) {
	dir := t.TempDir()

	// A USABLE hash with NO encrypted-password in config → passwordAction
	// returns pwLock, which is the branch under test. A locked hash would
	// return pwNoop and never reach the gate — an inert fixture.
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow,
		[]byte("root:*:19000:0:99999:7:::\nolga:$6$salt$livehash:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd,
		[]byte("root:x:0:0:root:/root:/bin/bash\nolga:x:1008:1008:,,,:/home/olga:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origShadow, origPasswd, origDir := shadowPath, passwdPath, provisionedUsersDir
	shadowPath, passwdPath = shadow, passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir = origShadow, origPasswd, origDir
	})

	// chpasswd must never run on an unproven claim; record it if it does.
	sentinel := filepath.Join(dir, "chpasswd-ran")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"),
		[]byte("#!/bin/sh\ncat > "+sentinel+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	unreadableMarkerPath(t, provisionedPasswordsDir(), "olga")

	d := &Daemon{}
	err := d.reconcileUserPassword(&config.LoginUser{Name: "olga", Class: "operator"})

	if err == nil {
		t.Fatal("reconcileUserPassword reported SUCCESS for a declarative password " +
			"LOCK whose ownership marker could not be read. olga's password is " +
			"still usable, but the apply converged (#6798)")
	}
	if !strings.Contains(err.Error(), "determine password ownership for olga") {
		t.Errorf("error = %v, want it to name the password-ownership determination "+
			"failure for olga", err)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Error("chpasswd RAN on an unreadable ownership marker — xpf locked an " +
			"account whose password it cannot prove it set (#6797 overclaim)")
	}
}

// TestRootKeyRevokeUnreadableMarkerDoesNotConverge_6798 pins the rootOwnErr
// gate in applyRootAuth.
//
// Root is the highest-consequence case in both directions: skipping silently
// leaves root key login live after the operator removed the keys from config,
// while revoking on an unproven claim can delete the operator's own
// out-of-band root key and lock them out of the box entirely. The gate must
// therefore report WITHOUT revoking.
//
// FAIL-ON-REVERT: drop the `else if rootOwnErr != nil { fail(...) }` arm and
// this REDS — the chain falls through to `else if rootOwnsKeys` with a false
// and applyRootAuth returns nil.
func TestRootKeyRevokeUnreadableMarkerDoesNotConverge_6798(t *testing.T) {
	_, rootKeys := stageRootAuthEnv(t, "*")
	writeRootKeys(t, rootKeys, rootKeyContent)

	unreadableMarkerPath(t, provisionedKeysDir(), "root")

	// root-authentication present but the key list is EMPTY → the revoke arm.
	d := &Daemon{}
	err := d.applyRootAuth(rootAuthCfg(""))

	if err == nil {
		t.Fatal("applyRootAuth reported SUCCESS after the root key list was emptied " +
			"but root's key-ownership marker could not be read. " +
			"/root/.ssh/authorized_keys is still on disk, so key-based root login " +
			"is NOT revoked, yet the apply converged (#6798)")
	}
	if !strings.Contains(err.Error(), "determine root key ownership") {
		t.Errorf("error = %v, want it to name the root key-ownership determination "+
			"failure", err)
	}
	if _, statErr := os.Stat(rootKeys); statErr != nil {
		t.Errorf("root authorized_keys was REMOVED on unreadable ownership (%v). "+
			"If that file is the operator's own out-of-band root key this is a "+
			"total lockout (#6797 overclaim)", statErr)
	}
}

// TestReconcileSudoersReportsUnreadableDir_6798 pins the ReadDir error split in
// reconcileSudoers — the third inventory R58 names, and the one whose error was
// discarded outright with `entries, _ :=`.
//
// FAIL-ON-REVERT: restore `entries, _ := os.ReadDir(sudoersDir)` and the
// UNREADABLE subtest REDS. The ABSENT subtest is the paired control: a host
// with no /etc/sudoers.d has no grants to revoke, so it MUST stay nil — a
// reconciler that errored on both would report a permanent bogus failure on
// every apply.
func TestReconcileSudoersReportsUnreadableDir_6798(t *testing.T) {
	t.Run("absent sudoers dir is a clean determination", func(t *testing.T) {
		dir := t.TempDir()
		origDir, origValidate := sudoersDir, validateSudoersFile
		sudoersDir = filepath.Join(dir, "does-not-exist")
		validateSudoersFile = func(string) error { return nil }
		t.Cleanup(func() { sudoersDir, validateSudoersFile = origDir, origValidate })

		d := &Daemon{}
		if err := d.reconcileSudoers(loginCfg()); err != nil {
			t.Errorf("reconcileSudoers with an ABSENT sudoers.d = %v, want nil: no "+
				"drop-in can exist in a directory that does not, so there is "+
				"nothing to revoke", err)
		}
	})

	t.Run("unreadable sudoers dir is reported", func(t *testing.T) {
		dir := t.TempDir()
		origDir, origValidate := sudoersDir, validateSudoersFile
		sudoersDir = filepath.Join(dir, "sudoers.d")
		validateSudoersFile = func(string) error { return nil }
		t.Cleanup(func() { sudoersDir, validateSudoersFile = origDir, origValidate })

		unreadableRootDir(t, sudoersDir)

		// No super-users in config: every xpf-<user> grant on disk is stale and
		// the sweep is supposed to revoke it.
		d := &Daemon{}
		err := d.reconcileSudoers(loginCfg())

		if err == nil {
			t.Fatal("reconcileSudoers reported SUCCESS over a sudoers.d it could not " +
				"read. The revocation sweep iterated an empty slice, so a demoted " +
				"or removed admin's xpf-<user> NOPASSWD grant is still live, and " +
				"the closeout sees convergence (#6798)")
		}
		if !strings.Contains(err.Error(), "read sudoers inventory") {
			t.Errorf("error = %v, want it to name the unreadable sudoers inventory", err)
		}
	})
}

// TestHostAuthCloseoutSurfacesUnreadableInventory_6798 is the END-TO-END cell:
// it binds the consequence R58 actually names — "unknown ownership inventory
// state must retain debt and PREVENT A SUCCESSFUL CLOSEOUT".
//
// The nine cells above prove each reconciler RETURNS an error. That is only
// half the property, because on the normal apply path every one of those
// returns is deliberately discarded (`_ = d.reconcileAbsentLoginUsers(cfg)` in
// applyTailReconciles — the #2926 next-boot convergence contract). The single
// caller that CONSUMES them is the #5874/M35 daemon-stop cancel closeout, which
// is precisely the moment next-boot convergence does NOT happen. If the error
// did not reach it, the fix would report into a void at the one site that
// matters.
//
// Only "absent-login-users" is a real reconciler here; the other six owners are
// clean no-ops, so a green cannot come from some unrelated owner failing — the
// closeout error must be attributable to THIS condition. The control run
// (readable inventory, same owners) pins nil, so an owner that failed for an
// environmental reason would break the control instead of silently passing the
// assertion.
//
// FAIL-ON-REVERT: revert any of M3 (provisionedNames error accumulation) or M4
// (reconcileAbsentLoginUsers invErr join) and this REDS — the owner returns nil
// and the cancel reports CLEAN over an inventory it could not read.
func TestHostAuthCloseoutSurfacesUnreadableInventory_6798(t *testing.T) {
	dir := t.TempDir()
	orig := provisionedUsersDir
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { provisionedUsersDir = orig })

	// The keys root is unreadable; the other two are genuinely absent.
	unreadableRootDir(t, provisionedKeysDir())

	d := &Daemon{}
	cfg := loginCfg()
	owners := []hostAuthOwner{
		{"lo0-filter", noopCloseoutOwner},
		{"host-inbound-filter", noopCloseoutOwner},
		{"system-login", noopCloseoutOwner},
		{"sudoers", noopCloseoutOwner},
		{"absent-login-users", d.reconcileAbsentLoginUsers}, // REAL reconciler
		{"ssh-config", noopCloseoutOwner},
		{"root-auth", noopCloseoutOwner},
	}

	err := summarizeHostAuthCloseout(
		runHostAuthCloseoutOwners(cfg, hostAuthCloseoutBudget, owners), hostAuthCloseoutBudget)
	if err == nil {
		t.Fatal("the host-auth cancel closeout returned CLEAN over an ownership " +
			"inventory it could not read. The daemon is stopping, so next-boot " +
			"convergence will NOT happen, and a removed operator's credentials " +
			"stay live behind a cancel that reported success (#6798)")
	}
	if !strings.Contains(err.Error(), "absent-login-users") {
		t.Errorf("closeout error %q does not attribute the failure to the "+
			"absent-login-users owner", err)
	}
	if !strings.Contains(err.Error(), "read ownership inventory") {
		t.Errorf("closeout error %q does not carry the unreadable-inventory "+
			"reason; the operator is left to guess which of the owner's failure "+
			"modes fired", err)
	}

	// Control: a fully READABLE (absent) inventory over the SAME owner set must
	// be clean. Without this, an owner failing for an environmental reason would
	// satisfy the assertion above and the cell would pass proving nothing.
	//
	// The control needs a fresh PARENT, not just a fresh leaf: the three roots
	// are siblings computed from filepath.Dir(provisionedUsersDir), so pointing
	// provisionedUsersDir at a sibling of the broken tree would still resolve
	// provisionedKeysDir() to the same unreadable file and the control would
	// red for the fixture's reason rather than the code's.
	provisionedUsersDir = filepath.Join(dir, "fresh", "provisioned-users")
	if err := summarizeHostAuthCloseout(
		runHostAuthCloseoutOwners(cfg, hostAuthCloseoutBudget, owners), hostAuthCloseoutBudget); err != nil {
		t.Fatalf("closeout returned %v over a readable (fresh-install) inventory, "+
			"want nil — a fresh install must not fail the cancel", err)
	}
}

// TestUnreadableInventoryErrorDoesNotSkipPeerSync_6798 binds the COMPOSITION
// with #6790, which neither lane could see from its own diff.
//
// #6798 adds no commit-time gate of its own. What makes these errors
// commit-failing is #6790: applyTailReconciles now CAPTURES the five
// host-credential returns instead of discarding them (`_ = d.reconcileSudoers`).
// So the #1960 no-brick argument cannot rest on "the caller discards the
// return" — that premise died the moment #6790 merged. It rests instead on the
// SHAPE OF THE REJECTION SET: applyErrSkipsPeerSync closes it over exactly two
// fatal classes, a required-protocol-gate error (dataplane disarmed) and a
// context cancel/deadline from a daemon-stop abort. Every other error still
// syncs with the config committed, active, and the dataplane armed.
//
// The error here is the REAL one the production path produces, not a synthetic
// stand-in: a synthetic errors.New would prove only that applyErrSkipsPeerSync
// rejects strings, while the actual question is what os.ReadDir's ENOTDIR
// becomes after provisionedNames wraps it and reconcileAbsentLoginUsers joins
// it.
//
// The two positive controls are load-bearing. Without them a mutation making
// applyErrSkipsPeerSync `return false` unconditionally would satisfy the main
// assertion vacuously — and that mutation is precisely the one that WOULD
// brick, by pushing a dataplane-disarming config to the standby.
//
// FAIL-ON-REVERT: this cell reds if applyErrSkipsPeerSync is ever widened to
// swallow a generic subsystem error (main assertion) or narrowed so a real
// fatal class stops skipping (controls).
func TestUnreadableInventoryErrorDoesNotSkipPeerSync_6798(t *testing.T) {
	dir := t.TempDir()
	orig := provisionedUsersDir
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { provisionedUsersDir = orig })
	unreadableRootDir(t, provisionedKeysDir())

	d := &Daemon{}
	err := d.reconcileAbsentLoginUsers(loginCfg())
	if err == nil {
		t.Fatal("fixture is inert: the unreadable inventory produced no error, so " +
			"this cell would assert nothing about the real error class")
	}

	if applyErrSkipsPeerSync(err) {
		t.Fatalf("an unreadable-inventory failure (%v) is classified as a "+
			"peer-sync-skipping FATAL error. It is neither a required-protocol-gate "+
			"error nor a daemon-stop abort, so the config is committed, active and "+
			"the dataplane armed — refusing to sync it would strand the peer on a "+
			"stale config over a filesystem read hiccup (#1960 no-brick, #6798 x #6790)", err)
	}

	// Controls: the two classes that MUST still skip. Without these the
	// assertion above is satisfied by an applyErrSkipsPeerSync that returns
	// false for everything — the mutation that would actually brick.
	if !applyErrSkipsPeerSync(context.Canceled) {
		t.Error("context.Canceled no longer skips peer sync; a daemon-stop abort " +
			"would push a half-applied config at the peer")
	}
	if !applyErrSkipsPeerSync(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded no longer skips peer sync")
	}
}
