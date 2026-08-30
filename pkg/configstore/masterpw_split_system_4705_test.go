package configstore

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// splitStanzaMasterPwText is a config whose master-password lives ONLY in a
// SECOND top-level system stanza (the #4705 reachability shape). Parsed with
// the real parser, tree.Children holds two `system` nodes.
const splitStanzaMasterPwText = `system {
    host-name split-secret-fw;
}
system {
    master-password {
        pseudorandom-function juniper-prf1;
    }
}
`

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
	tree, errs := config.NewParser(splitStanzaMasterPwText).Parse()
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

// TestMasterPasswordSplitStanzaDowngradeWarn_4705 proves the #4705 fix also
// repairs the #4579 A4-06 plaintext-downgrade warning for the split-stanza
// case: the warning path (db.go readTreeMeta) keys off masterPasswordPRF, so
// with the buggy first-match resolver a config that declares master-password
// ONLY in a second system stanza but is stored as plaintext read back WITHOUT
// any warning — the silent at-rest exposure #4579 was built to surface. Reuses
// the #4579 harness (captureWarnLogs / wrapEnvelope). RED on revert: first-
// match masterPasswordPRF returns "" for this tree, the warn never fires, and
// the substring assertion fails.
func TestMasterPasswordSplitStanzaDowngradeWarn_4705(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)

	tree, errs := config.NewParser(splitStanzaMasterPwText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs[0])
	}
	if masterPasswordPRF(tree) != "juniper-prf1" {
		t.Fatalf("split-stanza tree must declare a master-password (second stanza)")
	}

	// Write active.json as PLAINTEXT (no AES-GCM envelope) despite the declared
	// master-password — the downgrade case — wrapped in the #1917 compat
	// envelope like a real committed DB so readTreeMeta reaches decrypt/parse.
	body, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	framed := wrapEnvelope(body, "", true, EnvelopeMinReaderVersion)
	if err := fsatomic.WriteFileDurable(s.db.activePath(), framed, 0600); err != nil {
		t.Fatalf("write plaintext active.json: %v", err)
	}

	if _, err := s.db.ReadActive(); err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	logged := buf.String()
	if !strings.Contains(logged, "#4579") || !strings.Contains(logged, "UNENCRYPTED plaintext") {
		t.Fatalf("expected #4579 downgrade warning for split-stanza master-password; got log:\n%s", logged)
	}
}
