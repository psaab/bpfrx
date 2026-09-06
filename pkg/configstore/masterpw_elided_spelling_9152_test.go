package configstore

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9152: TWO SUPPORTED SPELLINGS OF `system master-password` SKIPPED AT-REST
// ENCRYPTION ENTIRELY. active.json and confirm.json were written in CLEARTEXT —
// including IKE pre-shared keys — on a clean commit, with no warning at any
// level, while `show configuration` rendered the stanza back to the operator.
//
// masterPasswordPRF asks two questions in order. #8898 fixed the SECOND
// (choose a supported algorithm) and left the FIRST (must we encrypt at all?)
// raw-scanning, so the two disagreed about the same tree:
//
//	                  Q1 configured   Q2 effective PRF   result
//	braced            true            juniper-prf1       encrypted
//	stanza elided     FALSE           juniper-prf1       PLAINTEXT
//	fully elided      FALSE           juniper-prf1       PLAINTEXT
//
// masterPasswordPRFOfNode reads `pseudorandom-function` as a CHILD of
// `master-password`; in a packed spelling the token is on the parent's Keys.
//
// This is not "the wrong KDF was chosen" — it is no encryption at all, and the
// only observable is reading the raw DB file.

const secret9152 = "s3cret-psk-9152"

func treeWithSecret9152(t *testing.T, masterPassword string) *config.ConfigTree {
	t.Helper()
	text := masterPassword + `
security {
	ike {
		policy p1 {
			pre-shared-key ascii-text "` + secret9152 + `";
		}
	}
}`
	root, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return &config.ConfigTree{Children: root.Children}
}

// TestEveryMasterPasswordSpellingEncryptsAtRest9152 is the end-to-end
// assertion: the secret must not appear verbatim in the persisted file.
//
// The two questions are ALSO asserted to agree, because a fix that made Q1
// return true for the wrong reason would satisfy the on-disk check while
// leaving the internal contradiction that produced this defect.
func TestEveryMasterPasswordSpellingEncryptsAtRest9152(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stanza  string
		wantPRF string
	}{
		// The control. This spelling always worked, and without it a fix that
		// simply encrypted everything would pass every row below.
		{"braced", `system { master-password { pseudorandom-function juniper-prf1; } }`, "juniper-prf1"},
		// The two defective spellings.
		{"stanza brace elided", `system { master-password pseudorandom-function juniper-prf1; }`, "juniper-prf1"},
		{"fully elided", `system master-password pseudorandom-function juniper-prf1;`, "juniper-prf1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := treeWithSecret9152(t, tc.stanza)

			if !masterPasswordConfigured(tree) {
				t.Errorf("Q1 (must we encrypt?) says NO for a config that carries a " +
					"master-password — this is the #9152 defect")
			}
			if got := effectiveMasterPasswordPRF(tree); got != tc.wantPRF {
				t.Errorf("Q2 (which algorithm?) = %q, want %q", got, tc.wantPRF)
			}
			if got := masterPasswordPRF(tree); got != tc.wantPRF {
				t.Fatalf("masterPasswordPRF = %q, want %q — an empty result means the DB is "+
					"written in PLAINTEXT", got, tc.wantPRF)
			}

			dir := t.TempDir()
			db, err := NewDB(dir)
			if err != nil {
				t.Fatalf("NewDB: %v", err)
			}
			if err := db.WriteActive(tree); err != nil {
				t.Fatalf("WriteActive: %v", err)
			}
			raw, err := os.ReadFile(db.activePath())
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if strings.Contains(string(raw), secret9152) {
				t.Errorf("the IKE pre-shared key is on disk IN CLEARTEXT despite a configured "+
					"master-password (#9152). Spelling: %s", tc.stanza)
			}
			if !strings.Contains(string(raw), encryptedTreeFormat) {
				t.Errorf("the persisted config carries no encryption envelope marker")
			}
			// It must still READ BACK. An "encryption" that cannot round-trip
			// would satisfy both checks above and brick the node.
			got, err := db.ReadActive()
			if err != nil {
				t.Fatalf("ReadActive: %v", err)
			}
			if got.FormatJSON() != tree.FormatJSON() {
				t.Errorf("the encrypted config did not round-trip")
			}
		})
	}
}

// TestMasterPasswordAbsenceStillMeansPlaintext9152 is the negative control for
// the whole change: a config with NO master-password must not start encrypting,
// or the fix is "encrypt everything" and proves nothing about the spellings.
func TestMasterPasswordAbsenceStillMeansPlaintext9152(t *testing.T) {
	tree := treeWithSecret9152(t, `system { host-name fw1; }`)
	if masterPasswordConfigured(tree) {
		t.Error("Q1 says a config with no master-password requires encryption")
	}
	if got := masterPasswordPRF(tree); got != "" {
		t.Errorf("masterPasswordPRF = %q for a config with no master-password, want \"\"", got)
	}
}

// TestDormantMasterPasswordStillForcesEncryption9152 pins the BOUND on the fix.
// Q1 is a deliberately BROAD fail-closed scan: an inactive or unapplied-group
// master-password still forces encryption, and folding compact spellings must
// not narrow that. #4705 and #5231 are the reasons it is broad.
func TestDormantMasterPasswordStillForcesEncryption9152(t *testing.T) {
	tree := treeWithSecret9152(t, `system { inactive: master-password { pseudorandom-function juniper-prf1; } }`)
	if !masterPasswordConfigured(tree) {
		t.Error("an INACTIVE master-password no longer forces encryption — the fold narrowed " +
			"a scan that is deliberately broad (#4705, #5231)")
	}
	if got := masterPasswordPRF(tree); got == "" {
		t.Error("a dormant master-password resolved to plaintext; it must fall back to a " +
			"supported default and still encrypt")
	}
}
