package daemon

// #5111 fail-on-revert: the syslog reconcile removes stale xpf-managed rsyslog
// drop-ins, but the `changed` flag (which gates the single `systemctl restart
// rsyslog`) was set ONLY when a desired file was (re)written. Removing the FINAL
// managed destination makes the desired set empty, so the write loop never runs
// and `changed` stayed false — the restart was skipped and rsyslog kept the
// deleted rule loaded (logs kept flowing to a removed destination). These tests
// drive reconcileSyslogDropins directly against a temp dir and assert that a
// real removal flips `changed` (so the restart fires) while a steady-state
// no-op does not.

import (
	"os"
	"path/filepath"
	"testing"
)

const syslogPrefix = "10-xpf-"

// TestReconcileSyslogDropins_RemoveFinalDest_5111 seeds a single managed
// drop-in and reconciles to an EMPTY desired set (final destination removed).
// The file must be removed AND `changed` must be true so the caller fires the
// rsyslog restart. Reverting the remove-sets-changed logic makes `changed`
// stay false and this test fails.
func TestReconcileSyslogDropins_RemoveFinalDest_5111(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, syslogPrefix+"audit.conf")
	if err := os.WriteFile(managed, []byte("# Managed by xpf — do not edit\n*.*\t/var/log/audit\n"), 0644); err != nil {
		t.Fatalf("seed managed drop-in: %v", err)
	}

	changed := reconcileSyslogDropins(dir, syslogPrefix, map[string]string{})

	if !changed {
		t.Errorf("removing the final managed destination must set changed=true (so rsyslog restarts); got false")
	}
	if _, err := os.Stat(managed); !os.IsNotExist(err) {
		t.Errorf("stale managed drop-in not removed: stat err = %v", err)
	}
}

// TestReconcileSyslogDropins_NoOp_5111 reconciles a state that already matches
// desired: nothing is removed and nothing is written, so `changed` must stay
// false (no spurious restart every reconcile).
func TestReconcileSyslogDropins_NoOp_5111(t *testing.T) {
	dir := t.TempDir()
	content := "# Managed by xpf — do not edit\n*.info\t/var/log/keep\n"
	name := syslogPrefix + "keep.conf"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("seed managed drop-in: %v", err)
	}

	changed := reconcileSyslogDropins(dir, syslogPrefix, map[string]string{name: content})

	if changed {
		t.Errorf("steady-state reconcile (no remove, no write) must not set changed; got true")
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Errorf("matching managed drop-in must be preserved: %v", err)
	}
}

// TestReconcileSyslogDropins_Write_5111 preserves the original behavior: when a
// desired file is written, `changed` becomes true.
func TestReconcileSyslogDropins_Write_5111(t *testing.T) {
	dir := t.TempDir()
	content := "# Managed by xpf — do not edit\n*.*\t/var/log/new\n"
	name := syslogPrefix + "new.conf"

	changed := reconcileSyslogDropins(dir, syslogPrefix, map[string]string{name: content})

	if !changed {
		t.Errorf("writing a new managed drop-in must set changed=true; got false")
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("desired drop-in not written: %v", err)
	}
	if string(got) != content {
		t.Errorf("drop-in content = %q, want %q", got, content)
	}
}

// TestReconcileSyslogDropins_RemoveOneKeepAnother_5111 removes one managed
// destination while another remains desired: the stale file is deleted and
// `changed` is set even though the surviving file needs no rewrite.
func TestReconcileSyslogDropins_RemoveOneKeepAnother_5111(t *testing.T) {
	dir := t.TempDir()
	keepContent := "# Managed by xpf — do not edit\n*.*\t/var/log/keep\n"
	keepName := syslogPrefix + "keep.conf"
	staleName := syslogPrefix + "stale.conf"
	if err := os.WriteFile(filepath.Join(dir, keepName), []byte(keepContent), 0644); err != nil {
		t.Fatalf("seed keep drop-in: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, staleName), []byte("# Managed by xpf — do not edit\n*.*\t/var/log/stale\n"), 0644); err != nil {
		t.Fatalf("seed stale drop-in: %v", err)
	}
	// A non-managed neighbor must be left untouched and must not set changed.
	other := filepath.Join(dir, "50-default.conf")
	if err := os.WriteFile(other, []byte("*.* /var/log/syslog\n"), 0644); err != nil {
		t.Fatalf("seed non-managed file: %v", err)
	}

	changed := reconcileSyslogDropins(dir, syslogPrefix, map[string]string{keepName: keepContent})

	if !changed {
		t.Errorf("removing a stale managed destination must set changed=true; got false")
	}
	if _, err := os.Stat(filepath.Join(dir, staleName)); !os.IsNotExist(err) {
		t.Errorf("stale drop-in not removed: stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, keepName)); err != nil {
		t.Errorf("kept drop-in must survive: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("non-managed file must not be removed: %v", err)
	}
}
