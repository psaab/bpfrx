package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPasswordAction is the central #1944 safety-invariant table test
// (§7.6): fail-OPEN toward applying a real password, fail-CLOSED (noop) on
// a read error in the lock branch so a transient /etc/shadow read failure
// can never lock out an operator.
func TestPasswordAction(t *testing.T) {
	cases := []struct {
		name    string
		cur     string
		ok      bool
		desired string
		want    pwAction
	}{
		{"set, mismatch -> apply", "$6$old$x", true, "$6$new$y", pwApply},
		{"set, match -> noop", "$6$same$z", true, "$6$same$z", pwNoop},
		{"set, read-fail -> apply (fail-open)", "", false, "$6$new$y", pwApply},
		{"set, missing entry -> apply", "", true, "$6$new$y", pwApply},
		{"empty, passwordless -> lock", "", true, "", pwLock},
		{"empty, usable hash -> lock", "$6$x$y", true, "", pwLock},
		{"empty, locked ! -> noop", "!", true, "", pwNoop},
		{"empty, locked !! -> noop", "!!", true, "", pwNoop},
		{"empty, locked * -> noop", "*", true, "", pwNoop},
		{"empty, locked !hash -> noop", "!$6$x$y", true, "", pwNoop},
		{"empty, read-fail -> noop (no lockout)", "", false, "", pwNoop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := passwordAction(tc.cur, tc.ok, tc.desired); got != tc.want {
				t.Errorf("passwordAction(%q,%v,%q) = %v, want %v",
					tc.cur, tc.ok, tc.desired, got, tc.want)
			}
		})
	}
}

func TestIsLockedShadow(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false}, // passwordless = most permissive, NOT locked
		{"*", true},
		{"!", true},
		{"!!", true},
		{"!$6$x$y", true},
		{"$6$x$y", false},
	}
	for _, tc := range cases {
		if got := isLockedShadow(tc.in); got != tc.want {
			t.Errorf("isLockedShadow(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestProvenanceMarkerUIDKeyed covers the UID-keyed provenance marker that
// dissolves the leave-rejoin vs out-of-band-recreate tension without any GC
// pass (#1944 §5.4 / §7.9).
func TestProvenanceMarkerUIDKeyed(t *testing.T) {
	dir := t.TempDir()
	old := provisionedUsersDir
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { provisionedUsersDir = old })

	// No marker → not provisioned.
	if xpfProvisioned("op", 1001) {
		t.Error("xpfProvisioned with no marker = true, want false")
	}

	// markProvisioned then matching UID → provisioned.
	if err := markProvisioned("op", 1001); err != nil {
		t.Fatalf("markProvisioned: %v", err)
	}
	if !xpfProvisioned("op", 1001) {
		t.Error("xpfProvisioned(op,1001) = false after mark, want true")
	}

	// Re-mark with same UID then UID mismatch (out-of-band recreate with a
	// different UID) → not provisioned, and the stale marker is cleaned.
	if err := markProvisioned("op", 1001); err != nil {
		t.Fatalf("markProvisioned: %v", err)
	}
	if xpfProvisioned("op", 2002) {
		t.Error("xpfProvisioned(op,2002) on UID mismatch = true, want false")
	}
	if _, err := os.Stat(markerPath("op")); !os.IsNotExist(err) {
		t.Error("stale marker not removed on UID mismatch")
	}

	// Leave-then-rejoin same account: re-mark, same UID still matches.
	if err := markProvisioned("op", 1001); err != nil {
		t.Fatalf("markProvisioned: %v", err)
	}
	if !xpfProvisioned("op", 1001) {
		t.Error("xpfProvisioned(op,1001) on rejoin = false, want true")
	}

	// Corrupt marker → not provisioned, cleaned.
	if err := os.WriteFile(markerPath("op"), []byte("not-a-number"), 0o600); err != nil {
		t.Fatalf("write corrupt marker: %v", err)
	}
	if xpfProvisioned("op", 1001) {
		t.Error("xpfProvisioned with corrupt marker = true, want false")
	}
	if _, err := os.Stat(markerPath("op")); !os.IsNotExist(err) {
		t.Error("corrupt marker not removed")
	}
}

// TestMarkerPathContainment verifies a username can never escape the
// provisioned-users directory (defensive Clean/Base).
func TestMarkerPathContainment(t *testing.T) {
	old := provisionedUsersDir
	provisionedUsersDir = "/var/lib/xpf/provisioned-users"
	t.Cleanup(func() { provisionedUsersDir = old })

	for _, name := range []string{"../../etc/shadow", "/etc/passwd", "a/b/c"} {
		got := markerPath(name)
		if dir := filepath.Dir(got); dir != provisionedUsersDir {
			t.Errorf("markerPath(%q) = %q escaped %q", name, got, provisionedUsersDir)
		}
	}
}

// TestCurrentShadowHashParse exercises the real currentShadowHash against a
// sample /etc/shadow via the injectable shadowPath (#1944 §7.8). The
// chpasswd exec itself is integration/live-only.
func TestCurrentShadowHashParse(t *testing.T) {
	dir := t.TempDir()
	shadow := filepath.Join(dir, "shadow")
	content := "root:$6$rootsalt$roothash:19000:0:99999:7:::\n" +
		"op:$6$opsalt$ophash:19000:0:99999:7:::\n" +
		"locked:!:19000:0:99999:7:::\n" +
		"empty::19000:0:99999:7:::\n"
	if err := os.WriteFile(shadow, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := shadowPath
	shadowPath = shadow
	t.Cleanup(func() { shadowPath = old })

	if h, ok := currentShadowHash("op"); !ok || h != "$6$opsalt$ophash" {
		t.Errorf("currentShadowHash(op) = %q,%v", h, ok)
	}
	if h, ok := currentShadowHash("locked"); !ok || h != "!" {
		t.Errorf("currentShadowHash(locked) = %q,%v", h, ok)
	}
	if h, ok := currentShadowHash("empty"); !ok || h != "" {
		t.Errorf("currentShadowHash(empty) = %q,%v", h, ok)
	}
	if _, ok := currentShadowHash("absent"); ok {
		t.Error("currentShadowHash(absent) ok = true, want false")
	}

	// Read error → ("", false).
	shadowPath = filepath.Join(dir, "does-not-exist")
	if _, ok := currentShadowHash("op"); ok {
		t.Error("currentShadowHash with missing file ok = true, want false")
	}
}

// TestReconcileApplyBoundaryRevalidatesHash proves the defense-in-depth
// re-validation in reconcileUserPassword (Codex #1944 r1 High #2): the
// lenient Load/SyncApply ingress only downgrades a ValidateCryptHash
// violation to a warning, so a persisted/synced plaintext value could
// otherwise reach `chpasswd -e`. The apply boundary MUST re-check the hash
// and skip the chpasswd exec for an invalid value, while still applying a
// valid one. We detect whether chpasswd ran by shadowing it with a fake on
// PATH that drops a sentinel file.
func TestReconcileApplyBoundaryRevalidatesHash(t *testing.T) {
	dir := t.TempDir()

	// Temp /etc/shadow + /etc/passwd so passwordAction decides pwApply
	// (op present with a DIFFERENT hash than desired) and lookupUID
	// succeeds.
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow, []byte("op:$6$old$existinghash:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("op:x:1001:1001:,,,:/home/op:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldShadow, oldPasswd, oldDir := shadowPath, passwdPath, provisionedUsersDir
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { shadowPath, passwdPath, provisionedUsersDir = oldShadow, oldPasswd, oldDir })

	// Fake chpasswd on PATH that records that it was invoked.
	sentinel := filepath.Join(dir, "chpasswd-ran")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ntouch " + sentinel + "\ncat >/dev/null\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	d := &Daemon{}

	// Invalid (plaintext) desired — guard must skip chpasswd entirely.
	d.reconcileUserPassword(&config.LoginUser{Name: "op", EncryptedPassword: "password12345"})
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("chpasswd ran for an INVALID (plaintext) hash — apply-boundary guard missing")
	}
	if _, err := os.Stat(markerPath("op")); err == nil {
		t.Fatal("provenance marker written despite skipped apply")
	}

	// Valid hash — chpasswd must run.
	d.reconcileUserPassword(&config.LoginUser{Name: "op", EncryptedPassword: "$6$newsalt$newhash"})
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("chpasswd did NOT run for a VALID hash — guard over-rejects")
	}
}

// TestLookupUID exercises the direct /etc/passwd UID parse via the
// injectable passwdPath.
func TestLookupUID(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	content := "root:x:0:0:root:/root:/bin/bash\n" +
		"op:x:1001:1001:,,,:/home/op:/bin/bash\n" +
		"bad:x:notanumber:1002::/home/bad:/bin/bash\n"
	if err := os.WriteFile(passwd, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := passwdPath
	passwdPath = passwd
	t.Cleanup(func() { passwdPath = old })

	if uid, ok := lookupUID("op"); !ok || uid != 1001 {
		t.Errorf("lookupUID(op) = %d,%v, want 1001,true", uid, ok)
	}
	if _, ok := lookupUID("absent"); ok {
		t.Error("lookupUID(absent) ok = true, want false")
	}
	if _, ok := lookupUID("bad"); ok {
		t.Error("lookupUID(bad) ok = true, want false (unparseable uid)")
	}
}
