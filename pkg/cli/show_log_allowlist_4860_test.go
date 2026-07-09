package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveShowLogPathAllowlist pins the CLI wiring for #4860: the
// interactive `show log <name>` path resolves the filename through the
// configured `system syslog file` allowlist (reading c.store.ActiveConfig())
// instead of shelling `tail` on any /var/log basename.
//
// RED on revert: restoring the inline filepath.Join("/var/log",
// filepath.Base(filename)) in showDaemonLog deletes resolveShowLogPath, so this
// test no longer compiles — and the intent (deny a non-allowlisted host log) is
// pinned here regardless.
func TestResolveShowLogPathAllowlist(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set system syslog file messages any any"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store}

	// The configured syslog file is readable.
	got, err := c.resolveShowLogPath("messages")
	if err != nil {
		t.Fatalf("resolveShowLogPath(messages) errored: %v (want allowed)", err)
	}
	if got != "/var/log/messages" {
		t.Fatalf("resolveShowLogPath(messages) = %q, want /var/log/messages", got)
	}

	// A view-only account cannot reach arbitrary host logs or traverse out.
	for _, name := range []string{"auth.log", "audit.log", "../../etc/shadow", "/etc/shadow"} {
		if _, err := c.resolveShowLogPath(name); err == nil {
			t.Errorf("resolveShowLogPath(%q) allowed; want refused", name)
		}
	}

	// A nil-store CLI fails closed.
	empty := &CLI{}
	if _, err := empty.resolveShowLogPath("messages"); err == nil || !strings.Contains(err.Error(), "messages") {
		t.Fatalf("resolveShowLogPath with nil store should refuse, got err=%v", err)
	}
}
