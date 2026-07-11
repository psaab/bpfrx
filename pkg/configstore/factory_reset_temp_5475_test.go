package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// zeroizeSecret5475 is a distinctive cleartext marker standing in for the IKE
// PSK / WireGuard key / SNMP community that a crash-leaked fsatomic temp would
// carry. It must not survive a factory reset.
const zeroizeSecret5475 = "ZEROIZE-SECRET-5475-crash-temp-psk"

// TestFactoryResetConfigDirRemovesFsatomicTemps pins #5475: the top-level sweep
// must also delete fsatomic crash-leaked write temps (".<base>.tmp-<rand>").
// fsatomic (pkg/fsatomic createTemp) names its pre-rename temp
// ".<base>.tmp-<random>"; a daemon killed mid-write leaves one at the top level
// of configDir still holding the FULL cleartext config text (xpf.conf /
// rescue.conf / a numbered rollback slot). Before this fix none of the sweep
// matchers (`.conf` suffix, `rollback` prefix, `.config.journal[.N]`, numbered
// text rollback slot) matched a name ending in "-<rand>", so the temp — and its
// secrets — survived the reset and the completing reboot.
//
// RED on revert: drop the `|| isFsatomicTemp(name)` clause and every temp below
// survives — the assertAbsent checks fail.
func TestFactoryResetConfigDirRemovesFsatomicTemps(t *testing.T) {
	dir := t.TempDir()
	configBase := "xpf.conf"
	marker := []byte(zeroizeSecret5475)

	// Crash-leaked fsatomic temps for every top-level base that fsatomic writes:
	// the live config, rescue.conf, a numbered rollback slot, and the audit
	// journal (whose base is itself ".config.journal", giving a double-dot temp).
	temps := []string{
		filepath.Join(dir, ".xpf.conf.tmp-abc123"),
		filepath.Join(dir, ".rescue.conf.tmp-DEADBEEF"),
		filepath.Join(dir, ".xpf.conf.1.tmp-0f0f"),
		filepath.Join(dir, "..config.journal.tmp-99"),
	}
	for _, p := range temps {
		if err := os.WriteFile(p, marker, 0o600); err != nil {
			t.Fatalf("seed temp %s: %v", p, err)
		}
	}

	// Normal artifacts handled by the pre-existing rules, to confirm they are
	// still removed alongside the new temp sweep.
	liveConf := filepath.Join(dir, configBase)
	rescue := filepath.Join(dir, "rescue.conf")
	textRollback := filepath.Join(dir, configBase+".1")
	journal := filepath.Join(dir, ".config.journal")
	for _, p := range []string{liveConf, rescue, textRollback, journal} {
		if err := os.WriteFile(p, marker, 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	// A legitimate non-temp dotfile must NOT be swept — isFsatomicTemp must be
	// narrow enough to leave unrelated dotfiles alone.
	keep := filepath.Join(dir, ".keepme")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatalf("seed keepme: %v", err)
	}
	// And a plain bystander (already guarded by the sibling test, re-asserted).
	bystander := filepath.Join(dir, "node-id")
	if err := os.WriteFile(bystander, []byte("0"), 0o600); err != nil {
		t.Fatalf("seed bystander: %v", err)
	}

	if err := FactoryResetConfigDir(dir, configBase); err != nil {
		t.Fatalf("FactoryResetConfigDir: %v", err)
	}

	// Every crash-leaked temp is gone (the fix; RED on revert).
	for _, p := range temps {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected fsatomic temp %s absent after factory reset, stat err = %v", p, err)
		}
	}
	// The normal artifacts are still removed by their own rules.
	for _, p := range []string{liveConf, rescue, textRollback, journal} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s absent after factory reset, stat err = %v", p, err)
		}
	}
	// Scope guards: the non-temp dotfile and the plain bystander survive.
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("factory reset removed a legitimate non-temp dotfile %s: %v", keep, err)
	}
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("factory reset removed a non-xpf file %s: %v", bystander, err)
	}
}

// TestIsFsatomicTemp pins the crash-leaked-temp recognizer: it matches the
// ".<base>.tmp-<rand>" shape fsatomic writes (any base, including double-dot
// journal temps and numbered rollback-slot temps) without eating legitimate
// dotfiles or the normal config artifacts.
func TestIsFsatomicTemp(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{".xpf.conf.tmp-abc123", true},      // live config temp
		{".rescue.conf.tmp-DEADBEEF", true}, // rescue temp
		{".xpf.conf.1.tmp-0f0f", true},      // rollback-slot temp
		{"..config.journal.tmp-99", true},   // journal temp (double dot)
		{".xpf.conf.tmp-", true},            // empty random suffix (still a temp)
		{"xpf.conf", false},                 // live config (no leading dot / .tmp-)
		{"xpf.conf.1", false},               // text rollback slot
		{".config.journal", false},          // audit journal (no .tmp-)
		{".config.journal.1", false},        // rotated journal segment
		{".keepme", false},                  // unrelated dotfile
		{"node-id", false},                  // plain bystander
		{"xpf.conf.tmp-abc", false},         // no leading dot — not an fsatomic temp
		{".tmp-abc", false},                 // no ".tmp-" (needs a base before it)
	}
	for _, tc := range cases {
		if got := isFsatomicTemp(tc.name); got != tc.want {
			t.Errorf("isFsatomicTemp(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
