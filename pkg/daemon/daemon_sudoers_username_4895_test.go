package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4895 defense-in-depth: even if a crafted `system login user <name>` slips
// past the strict commit-check (e.g. the tolerant load / peer-sync path
// downgrades the schema gate to a warning per #1960), the daemon's sudoers
// writer must NEVER format an unvalidated name into an /etc/sudoers.d grant.
// The config lexer decodes `\n` in a quoted string into a literal newline, so
// a name like "x\nnobody ALL=(ALL) NOPASSWD: ALL" would otherwise inject a
// second valid sudoers directive (unmodeled passwordless root).

// injectionName is the crafted key: an embedded newline followed by a second
// sudoers directive. In real config the lexer materializes this from a quoted
// "\n"; here the literal newline is the post-lexer form.
const injectionName = "x\nnobody ALL=(ALL) NOPASSWD: ALL"

// TestWriteSudoersGrantRefusesInjection proves writeSudoersGrant refuses a name
// that fails ValidateLoginUsername and never writes a file. RED on revert: drop
// the guard and the durable write proceeds, installing the injected directive.
func TestWriteSudoersGrantRefusesInjection(t *testing.T) {
	dir := withSudoersTestDir(t)

	if err := writeSudoersGrant(injectionName); err == nil {
		t.Fatal("writeSudoersGrant accepted an injection username — must refuse")
	}
	// No file may have been written under the managed namespace.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("writeSudoersGrant wrote %d file(s) for an invalid name, want 0: %v", len(entries), entries)
	}
}

// TestWriteSudoersGrantAcceptsNormal proves the guard does not regress the
// normal path: a valid name still gets its grant with the expected content.
func TestWriteSudoersGrantAcceptsNormal(t *testing.T) {
	dir := withSudoersTestDir(t)

	if err := writeSudoersGrant("admin"); err != nil {
		t.Fatalf("writeSudoersGrant(admin) = %v, want nil", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "xpf-admin"))
	if err != nil {
		t.Fatalf("admin grant not written: %v", err)
	}
	if want := "admin ALL=(ALL) NOPASSWD: ALL\n"; string(got) != want {
		t.Errorf("admin grant = %q, want %q", got, want)
	}
}

// TestReconcileSudoersSkipsInjectionName proves reconcileSudoers skips a
// super-user whose name is unsafe: no drop-in is written and a valid peer in
// the same config still gets its grant.
func TestReconcileSudoersSkipsInjectionName(t *testing.T) {
	dir := withSudoersTestDir(t)
	d := &Daemon{}

	cfg := loginCfg(
		&config.LoginUser{Name: injectionName, Class: "super-user"},
		&config.LoginUser{Name: "admin", Class: "super-user"},
	)
	d.reconcileSudoers(cfg)

	// The injected directive must not appear anywhere in the managed namespace.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "xpf-admin" {
			continue
		}
		t.Errorf("unexpected sudoers file written for an invalid name: %q", e.Name())
	}
	// The valid peer still gets its grant.
	if got, err := os.ReadFile(filepath.Join(dir, "xpf-admin")); err != nil {
		t.Fatalf("valid peer admin grant not written: %v", err)
	} else if want := "admin ALL=(ALL) NOPASSWD: ALL\n"; string(got) != want {
		t.Errorf("admin grant = %q, want %q", got, want)
	}
}
