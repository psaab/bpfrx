package configstore

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMasterPasswordSplitSystemStanzaEncrypts is the #4705 regression guard.
//
// The Junos parser does not merge duplicate top-level `system {}` stanzas
// (parseStatements appends each), and LoadOverride / SyncApply feed the raw
// parsed tree straight to the write path. When `master-password` lives in a
// SECOND system stanza, a first-match masterPasswordPRF using
// tree.FindChild("system") resolved the PRF as empty and wrote the config DB
// in PLAINTEXT — leaking every configured secret to disk despite the operator
// enabling master-password encryption.
//
// The tree here is built with the real parser so it exercises the true
// reachability path: two `system` children coexist in tree.Children. Reverting
// the fix (walking every system stanza back to a single FindChild) makes this
// test FAIL — the persisted DB contains the cleartext host-name and lacks the
// encrypted envelope marker.
func TestMasterPasswordSplitSystemStanzaEncrypts(t *testing.T) {
	const cfgText = `system {
    host-name split-secret-fw;
}
system {
    master-password {
        pseudorandom-function juniper-prf1;
    }
}
`
	tree, errs := config.NewParser(cfgText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs[0])
	}

	// Reachability proof: the parser really does keep two separate `system`
	// nodes, and only the second carries master-password.
	systems := 0
	for _, n := range tree.Children {
		if n.Name() == "system" {
			systems++
		}
	}
	if systems != 2 {
		t.Fatalf("expected 2 top-level system stanzas from parser, got %d", systems)
	}
	if first := tree.FindChild("system"); first == nil || first.FindChild("master-password") != nil {
		t.Fatalf("test premise broken: first system stanza must NOT carry master-password")
	}

	// The PRF must resolve from the second stanza (fail-closed).
	if prf := masterPasswordPRF(tree); prf != "juniper-prf1" {
		t.Fatalf("masterPasswordPRF = %q, want %q (must scan all system stanzas)", prf, "juniper-prf1")
	}

	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive() error = %v", err)
	}

	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "split-secret-fw") {
		t.Fatalf("split-stanza config leaked plaintext to disk despite master-password: %s", string(raw))
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatalf("split-stanza config was not encrypted (missing envelope marker): %s", string(raw))
	}
	if _, err := os.Stat(db.masterKeyPath()); err != nil {
		t.Fatalf("master key was not created: %v", err)
	}

	// Round-trips back to the original tree.
	got, err := db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive() error = %v", err)
	}
	if got.FormatJSON() != tree.FormatJSON() {
		t.Fatalf("ReadActive() mismatch\ngot:\n%s\nwant:\n%s", got.FormatJSON(), tree.FormatJSON())
	}
}

// TestMasterPasswordSingleStanzaStillResolves guards the common case: a normal
// single `system` stanza with master-password must still resolve the PRF and
// encrypt (the fix must not regress the happy path).
func TestMasterPasswordSingleStanzaStillResolves(t *testing.T) {
	tree := testConfigTree("hmac-sha2-256", "single-stanza-fw")
	if prf := masterPasswordPRF(tree); prf != "hmac-sha2-256" {
		t.Fatalf("masterPasswordPRF = %q, want %q", prf, "hmac-sha2-256")
	}

	// And a config with no master-password anywhere resolves empty (plaintext).
	plain := testConfigTree("", "plain-fw")
	if prf := masterPasswordPRF(plain); prf != "" {
		t.Fatalf("masterPasswordPRF(no master-password) = %q, want empty", prf)
	}
}
