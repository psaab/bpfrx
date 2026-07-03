package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// withSudoersTestDir points reconcileSudoers at a throwaway directory and
// stubs the visudo validator (unit tests run non-root; the fixed template
// is always valid), restoring both on cleanup.
func withSudoersTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origDir := sudoersDir
	origValidate := validateSudoersFile
	sudoersDir = dir
	validateSudoersFile = func(string) error { return nil }
	t.Cleanup(func() {
		sudoersDir = origDir
		validateSudoersFile = origValidate
	})
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0440); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

func loginCfg(users ...*config.LoginUser) *config.Config {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Users: users}
	return cfg
}

// TestReconcileSudoersRevokesDowngradeAndRemoval is the #3889 RED-on-revert
// test. It seeds an initial super-user grant set, then applies a config in
// which one user is DOWNGRADED (super-user -> operator) and another is
// REMOVED entirely, and a new super-user is added. After the reconcile:
//   - the downgraded user's grant is REMOVED (RED on revert: without the
//     revocation sweep the stale file persists and the demoted admin keeps
//     passwordless root),
//   - the removed user's grant is REMOVED,
//   - the current super-user's grant is written with the correct content,
//   - a non-xpf sudoers.d file is left completely untouched.
func TestReconcileSudoersRevokesDowngradeAndRemoval(t *testing.T) {
	dir := withSudoersTestDir(t)
	d := &Daemon{}

	// Initial state on disk: alice + carol were super-users (grants exist),
	// plus an operator-authored drop-in that xpf must never touch.
	alice := filepath.Join(dir, "xpf-alice")
	carol := filepath.Join(dir, "xpf-carol")
	custom := filepath.Join(dir, "90-operator-custom")
	writeFile(t, alice, "alice ALL=(ALL) NOPASSWD: ALL\n")
	writeFile(t, carol, "carol ALL=(ALL) NOPASSWD: ALL\n")
	const customContent = "someuser ALL=(ALL) NOPASSWD: /bin/systemctl\n"
	writeFile(t, custom, customContent)

	// New config: alice downgraded to operator, carol removed entirely,
	// bob added as a super-user.
	cfg := loginCfg(
		&config.LoginUser{Name: "alice", Class: "operator"},
		&config.LoginUser{Name: "bob", Class: "super-user"},
	)

	d.reconcileSudoers(cfg)

	// Downgraded user's grant revoked.
	if _, err := os.Stat(alice); !os.IsNotExist(err) {
		t.Errorf("downgraded user alice: sudoers grant still present (err=%v) — stale privilege not revoked", err)
	}
	// Removed user's grant revoked.
	if _, err := os.Stat(carol); !os.IsNotExist(err) {
		t.Errorf("removed user carol: sudoers grant still present (err=%v) — stale privilege not revoked", err)
	}
	// Current super-user's grant written with correct content.
	bob := filepath.Join(dir, "xpf-bob")
	got, err := os.ReadFile(bob)
	if err != nil {
		t.Fatalf("current super-user bob: grant not written: %v", err)
	}
	if want := "bob ALL=(ALL) NOPASSWD: ALL\n"; string(got) != want {
		t.Errorf("bob grant = %q, want %q", got, want)
	}
	// Non-xpf operator file untouched.
	if got, err := os.ReadFile(custom); err != nil || string(got) != customContent {
		t.Errorf("operator-authored 90-operator-custom modified: content=%q err=%v", got, err)
	}
}

// TestReconcileSudoersKeepsCurrentSuperUser proves an unchanged current
// super-user's grant is (re)written/kept across an apply.
func TestReconcileSudoersKeepsCurrentSuperUser(t *testing.T) {
	dir := withSudoersTestDir(t)
	d := &Daemon{}

	cfg := loginCfg(&config.LoginUser{Name: "admin", Class: "super-user"})
	d.reconcileSudoers(cfg)

	admin := filepath.Join(dir, "xpf-admin")
	if got, err := os.ReadFile(admin); err != nil {
		t.Fatalf("first apply: admin grant not written: %v", err)
	} else if want := "admin ALL=(ALL) NOPASSWD: ALL\n"; string(got) != want {
		t.Fatalf("admin grant = %q, want %q", got, want)
	}

	// Idempotent second apply keeps it.
	d.reconcileSudoers(cfg)
	if _, err := os.Stat(admin); err != nil {
		t.Errorf("second apply: admin grant removed unexpectedly: %v", err)
	}
}

// TestReconcileSudoersAllUsersRemoved covers the config-with-no-login-users
// case: every xpf-managed grant must still be revoked even though
// applySystemLogin returns early (Login nil). Non-xpf files survive.
func TestReconcileSudoersAllUsersRemoved(t *testing.T) {
	dir := withSudoersTestDir(t)
	d := &Daemon{}

	stale := filepath.Join(dir, "xpf-ghost")
	custom := filepath.Join(dir, "10-keep-me")
	writeFile(t, stale, "ghost ALL=(ALL) NOPASSWD: ALL\n")
	const keep = "root ALL=(ALL) ALL\n"
	writeFile(t, custom, keep)

	// Login entirely absent from the config.
	cfg := &config.Config{}
	d.reconcileSudoers(cfg)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("xpf-ghost grant survived a no-users config (err=%v) — stale privilege not revoked", err)
	}
	if got, err := os.ReadFile(custom); err != nil || string(got) != keep {
		t.Errorf("non-xpf 10-keep-me modified: content=%q err=%v", got, err)
	}
}

// TestReconcileSudoersSkipsRoot proves a login user literally named root is
// never granted an xpf-managed drop-in.
func TestReconcileSudoersSkipsRoot(t *testing.T) {
	dir := withSudoersTestDir(t)
	d := &Daemon{}

	cfg := loginCfg(&config.LoginUser{Name: "root", Class: "super-user"})
	d.reconcileSudoers(cfg)

	if _, err := os.Stat(filepath.Join(dir, "xpf-root")); !os.IsNotExist(err) {
		t.Errorf("xpf-root grant written for a root login user (err=%v) — must be skipped", err)
	}
}
