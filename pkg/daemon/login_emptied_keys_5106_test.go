package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stageEmptiedKeysEnv points the account DBs + marker dir + home base at a
// throwaway tree, seeds /etc/passwd and a LOCKED /etc/shadow field for name
// (so reconcileUserPassword takes pwNoop and never execs chpasswd), and stubs
// runCommandTimeout so `id` reports the user already EXISTS — skipping the
// privileged useradd so the test runs cleanly unprivileged. It returns the
// managed authorized_keys path for name. #5106.
func stageEmptiedKeysEnv(t *testing.T, name string, uid int) string {
	t.Helper()
	dir := t.TempDir()

	shadow := filepath.Join(dir, "shadow")
	// A locked ("!") field means passwordAction returns pwNoop when the config
	// carries no encrypted-password, so no chpasswd is ever exec'd.
	shadowContent := fmt.Sprintf("root:*:19000:0:99999:7:::\n%s:!:19000:0:99999:7:::\n", name)
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
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = origShadow, origPasswd, origDir, origHome
	})

	origRun := runCommandTimeout
	runCommandTimeout = func(cmd string, args ...string) ([]byte, error) {
		// `id -- <name>` returning nil means "user exists" → useradd is
		// skipped. Every other command is an inert no-op; the emptied-keys
		// branch under test performs no external commands.
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })

	return managedAuthorizedKeysPath(name)
}

// TestApplySystemLoginRevokesEmptiedKeys is the #5106 fail-on-revert guard: a
// RETAINED login user whose SSH key list has been emptied in config must have
// its xpf-managed authorized_keys REMOVED so the revoked key can no longer log
// in. Reverting the empty-key-list else branch in applySystemLogin makes this
// RED — the stale key file survives.
func TestApplySystemLoginRevokesEmptiedKeys(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "alice", 1001)

	// alice was provisioned by xpf (marker UID matches) and a prior apply wrote
	// her managed authorized_keys — so the KEY-ownership marker is present
	// (#5841: the emptied-key removal is gated on the key marker).
	if err := markProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := markKeyProvisioned("alice", 1001); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAAC3... alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// alice is still configured, but her key list is now EMPTY.
	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{Name: "alice", Class: "operator"}))

	if _, err := os.Stat(keysFile); !os.IsNotExist(err) {
		t.Fatalf("managed authorized_keys still present after key list emptied (err=%v) — #5106 revocation missing", err)
	}
}

// TestApplySystemLoginKeepsNonProvisionedKeys proves the emptied-keys removal
// is scoped: a configured user with NO provenance marker (xpf never
// provisioned the account / never wrote its keys) must keep a pre-existing
// authorized_keys — xpf must not delete an operator-installed key file it does
// not own.
func TestApplySystemLoginKeepsNonProvisionedKeys(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "bob", 1002)

	// No markProvisioned("bob", ...) — xpf does not own this account.
	if err := os.MkdirAll(filepath.Dir(keysFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysFile, []byte("ssh-ed25519 AAAA bob-operator-installed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{Name: "bob", Class: "operator"}))

	if _, err := os.Stat(keysFile); err != nil {
		t.Fatalf("non-xpf user's authorized_keys was removed (err=%v) — the emptied-keys branch must only touch xpf-owned files", err)
	}
}

// TestApplySystemLoginEmptiedKeysIdempotent proves the emptied-keys branch is a
// no-op when the managed authorized_keys is already absent: an xpf-provisioned
// user configured without keys and with no key file present must not error or
// spuriously act. (RED would be a panic/removal side effect; GREEN is a clean
// pass with the file staying absent.)
func TestApplySystemLoginEmptiedKeysIdempotent(t *testing.T) {
	keysFile := stageEmptiedKeysEnv(t, "carol", 1003)
	if err := markProvisioned("carol", 1003); err != nil {
		t.Fatal(err)
	}
	// Deliberately do NOT create keysFile.

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{Name: "carol", Class: "operator"}))

	if _, err := os.Stat(keysFile); !os.IsNotExist(err) {
		t.Fatalf("authorized_keys unexpectedly present after an already-absent reconcile (err=%v)", err)
	}
}
