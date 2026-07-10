package configstore

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// groupMasterPwText declares master-password ONLY inside a `groups { enc {
// system { master-password ... } } }` body and activates it with
// `apply-groups enc`. There is NO top-level `system master-password`. Parsed
// with the real parser, tree.Children holds a `groups` node and an
// `apply-groups` node — the exact #5231 reachability shape.
const groupMasterPwText = `groups {
    enc {
        system {
            master-password {
                pseudorandom-function juniper-prf1;
            }
        }
    }
}
apply-groups enc;
system {
    host-name group-secret-fw;
}
`

// TestMasterPasswordViaApplyGroupsEncrypts is the #5231 regression guard.
//
// A master-password declared inside a group and pulled in via apply-groups is
// ACTIVE at runtime — compileConfigWithOpts expands apply-groups before
// compileSystem reads master-password, so the effective config sets
// sys.MasterPassword. But maybeEncryptTreeJSON runs on the UNEXPANDED persisted
// candidate tree, so a resolver that scans only top-level `system` stanzas
// (systemBlocksOf) sees no master-password, returns "", and writes active.json
// (all configured secrets) in PLAINTEXT despite encryption being configured.
//
// The tree is built with the real parser so it exercises the true reachability
// path: the master-password lives only under `groups { enc { system { ... }}}`
// with `apply-groups enc`. Reverting the fix (dropping the groups scan) makes
// this test FAIL — masterPasswordPRF returns "" and the persisted DB contains
// the cleartext host-name without the encrypted envelope marker.
func TestMasterPasswordViaApplyGroupsEncrypts(t *testing.T) {
	tree, errs := config.NewParser(groupMasterPwText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs[0])
	}

	// Reachability premise: no top-level system carries master-password; the
	// PRF is only reachable through the group body.
	for _, sys := range systemBlocksOf(tree) {
		if sys.FindChild("master-password") != nil {
			t.Fatalf("test premise broken: a top-level system stanza carries master-password")
		}
	}
	if len(groupsBlocksOf(tree)) == 0 {
		t.Fatalf("test premise broken: expected a top-level groups stanza from parser")
	}

	// Confirm the runtime actually ACTIVATES this group-declared master-password
	// (so the leaked secret is real, not a no-op): compiling the config expands
	// apply-groups and folds the group's master-password into the effective
	// system config.
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig() error = %v", err)
	}
	if cfg.System.MasterPassword != "juniper-prf1" {
		t.Fatalf("compiled System.MasterPassword = %q, want %q (apply-groups must activate it)",
			cfg.System.MasterPassword, "juniper-prf1")
	}

	// The at-rest encrypt gate must resolve the same PRF from the UNEXPANDED
	// tree (fail-closed).
	if prf := masterPasswordPRF(tree); prf != "juniper-prf1" {
		t.Fatalf("masterPasswordPRF = %q, want %q (must scan group bodies)", prf, "juniper-prf1")
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
	if strings.Contains(string(raw), "group-secret-fw") {
		t.Fatalf("apply-groups master-password config leaked plaintext to disk: %s", string(raw))
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatalf("apply-groups master-password config was not encrypted (missing envelope marker): %s", string(raw))
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

// TestMasterPasswordPRFSurfaces exercises masterPasswordPRF across the three
// resolution surfaces to lock in that the #5231 groups scan does not regress
// the top-level (#4705) or split-stanza behavior, and that a config with no
// master-password anywhere still resolves empty (plaintext).
func TestMasterPasswordPRFSurfaces(t *testing.T) {
	// Top-level single system stanza still resolves (happy path).
	if prf := masterPasswordPRF(testConfigTree("hmac-sha2-256", "top-level-fw")); prf != "hmac-sha2-256" {
		t.Fatalf("top-level masterPasswordPRF = %q, want %q", prf, "hmac-sha2-256")
	}

	// Split top-level system stanzas (#4705) still resolve.
	splitTree, errs := config.NewParser(splitStanzaMasterPwText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse split config: %v", errs[0])
	}
	if prf := masterPasswordPRF(splitTree); prf != "juniper-prf1" {
		t.Fatalf("split-stanza masterPasswordPRF = %q, want %q", prf, "juniper-prf1")
	}

	// A group that defines master-password but is NOT applied still triggers
	// encryption (fail-closed superset — a harmless false-positive encrypt).
	unappliedTree, errs := config.NewParser(`groups {
    enc {
        system {
            master-password {
                pseudorandom-function sha256;
            }
        }
    }
}
system {
    host-name unapplied-group-fw;
}
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse unapplied-group config: %v", errs[0])
	}
	if prf := masterPasswordPRF(unappliedTree); prf != "sha256" {
		t.Fatalf("unapplied-group masterPasswordPRF = %q, want %q (fail-closed)", prf, "sha256")
	}

	// No master-password anywhere resolves empty (plaintext, no encryption).
	if prf := masterPasswordPRF(testConfigTree("", "plain-fw")); prf != "" {
		t.Fatalf("no-master-password masterPasswordPRF = %q, want empty", prf)
	}
	plainGroups, errs := config.NewParser(`groups {
    other {
        system {
            host-name from-group;
        }
    }
}
apply-groups other;
system {
    host-name plain-with-groups-fw;
}
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse plain-groups config: %v", errs[0])
	}
	if prf := masterPasswordPRF(plainGroups); prf != "" {
		t.Fatalf("groups-without-master-password masterPasswordPRF = %q, want empty", prf)
	}
}
