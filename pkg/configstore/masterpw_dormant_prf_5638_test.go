package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5638 (codex-review-181 M30): masterPasswordPRF must never hand a DORMANT
// (inactive / unapplied-group) or UNSUPPORTED pseudorandom-function to the
// at-rest persistence write path. The #4578 commit gate validates the EFFECTIVE
// tree (inactive stripped, apply-groups expanded), so an unsupported PRF hidden
// in an inactive node or an unapplied group is never rejected at commit. The
// pre-fix fail-closed SUPERSET, however, scanned every group regardless of
// application state and returned that unsupported value; on the HA config-sync
// / tolerant-load path prfHash then rejected it, writeActive failed, and the
// singleton retry re-selected the same bad value forever — a deterministic,
// non-durable persistence failure (node stuck /health-503, authoritative
// generation never reaches disk).
//
// The fix separates "encryption is required" (broad, fail-closed) from "which
// PRF algorithm" (effective scope only, supported selector only, else the
// supported default). These tests fail on pre-fix code:
//   - the value tests: pre-fix masterPasswordPRF returns "bogus"/"sha512".
//   - the durability tests: pre-fix WriteActive/SyncApply cannot persist a
//     "bogus" selector (prfHash rejects it), leaving the store persist-degraded.

// unappliedGroupUnsupportedPRFText declares master-password ONLY inside an
// UNAPPLIED group body carrying an UNSUPPORTED selector `bogus`. No
// `apply-groups enc` references it, so it is dormant: the effective config has
// no master-password at all. This is the exact M30 shape a pre-#5231 build (or
// an inactive edit) could persist, then load after upgrade and push over HA
// config-sync.
const unappliedGroupUnsupportedPRFText = `groups {
    enc {
        system {
            master-password {
                pseudorandom-function bogus;
            }
        }
    }
}
system {
    host-name dormant-unsupported-fw;
}
`

// inactiveSupportedPRFText carries an INACTIVE master-password with a SUPPORTED
// but non-default selector `sha512`. The effective (inactive-stripped) config
// has no master-password, so the resolved algorithm must come from the default,
// not the dormant `sha512` — proving the effective-scope constraint
// independently of the unsupported-value path.
const inactiveSupportedPRFText = `system {
    host-name inactive-mp-fw;
    inactive: master-password {
        pseudorandom-function sha512;
    }
}
`

// TestMasterPasswordPRF_DormantUnsupportedResolvesSupported: a dormant
// (unapplied-group) UNSUPPORTED PRF still triggers encryption (fail-closed) but
// resolves to a SUPPORTED selector, never the raw `bogus` value. Pre-fix
// returns "bogus" (RED — both the not-bogus and prfSupported assertions fail).
func TestMasterPasswordPRF_DormantUnsupportedResolvesSupported(t *testing.T) {
	tree, errs := config.NewParser(unappliedGroupUnsupportedPRFText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs[0])
	}

	// Premise: the unsupported PRF is reachable ONLY through the group body;
	// no active top-level system carries it.
	for _, sys := range systemBlocksOf(tree) {
		if sys.FindChild("master-password") != nil {
			t.Fatalf("test premise broken: a top-level system stanza carries master-password")
		}
	}
	if len(groupsBlocksOf(tree)) == 0 {
		t.Fatalf("test premise broken: expected a top-level groups stanza")
	}

	// Encryption is still required (fail-closed): the belt must fire even for a
	// dormant master-password.
	if !masterPasswordConfigured(tree) {
		t.Fatal("masterPasswordConfigured = false, want true (a dormant master-password must still require encryption)")
	}

	prf := masterPasswordPRF(tree)
	if prf == "bogus" {
		t.Fatal("masterPasswordPRF returned the dormant UNSUPPORTED selector \"bogus\" — it would " +
			"deterministically fail the persistence write (#5638 M30)")
	}
	if !prfSupported(prf) {
		t.Fatalf("masterPasswordPRF = %q, which prfHash rejects — the write path must only ever "+
			"receive a supported selector", prf)
	}
	if prf != defaultMasterPasswordPRF {
		t.Fatalf("masterPasswordPRF = %q, want the supported default %q (dormant/unsupported PRF must "+
			"resolve to the default)", prf, defaultMasterPasswordPRF)
	}
}

// TestMasterPasswordPRF_IgnoresInactiveSupportedValue proves the effective-scope
// constraint: an INACTIVE master-password's supported selector (`sha512`) is
// ignored; the resolver returns the default because the effective config has no
// master-password. Pre-fix Surface-1 scan returns "sha512" (RED).
func TestMasterPasswordPRF_IgnoresInactiveSupportedValue(t *testing.T) {
	tree, errs := config.NewParser(inactiveSupportedPRFText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs[0])
	}

	// Premise: the master-password node parsed as inactive.
	sys := tree.FindChild("system")
	if sys == nil {
		t.Fatal("test premise broken: no system stanza")
	}
	mp := sys.FindChild("master-password")
	if mp == nil {
		t.Fatal("test premise broken: no master-password node")
	}
	if !mp.Inactive {
		t.Fatalf("test premise broken: master-password node is not inactive (Inactive=%v)", mp.Inactive)
	}

	// Fail-closed: an inactive master-password still triggers encryption.
	if !masterPasswordConfigured(tree) {
		t.Fatal("masterPasswordConfigured = false, want true (an inactive master-password must still require encryption)")
	}

	if prf := masterPasswordPRF(tree); prf != defaultMasterPasswordPRF {
		t.Fatalf("masterPasswordPRF = %q, want %q — the dormant inactive `sha512` must be ignored and "+
			"the effective scope resolves to the supported default (#5638)", prf, defaultMasterPasswordPRF)
	}
}

// TestWriteActive_DormantUnsupportedPRFDurable: DB.WriteActive of the
// dormant-unsupported config must SUCCEED, encrypt the body, and round-trip.
// Pre-fix WriteActive fails with an "unsupported master-password
// pseudorandom-function" error from prfHash (RED).
func TestWriteActive_DormantUnsupportedPRFDurable(t *testing.T) {
	tree, errs := config.NewParser(unappliedGroupUnsupportedPRFText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs[0])
	}

	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive() error = %v (a dormant unsupported PRF must not fail the write)", err)
	}

	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "dormant-unsupported-fw") {
		t.Fatalf("config leaked plaintext to disk despite a configured master-password: %s", string(raw))
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatalf("config was not encrypted (missing envelope marker): %s", string(raw))
	}

	got, err := db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive() error = %v", err)
	}
	if got.FormatJSON() != tree.FormatJSON() {
		t.Fatalf("ReadActive() mismatch\ngot:\n%s\nwant:\n%s", got.FormatJSON(), tree.FormatJSON())
	}
}

// TestSyncApply_DormantUnsupportedPRFStaysDurable is the strongest M30
// reproduction: an HA config-sync of a config whose ONLY master-password is a
// dormant unsupported PRF must persist durably — NOT leave the store
// persist-degraded on an endless retry. It also verifies the persisted config
// survives a restart (a fresh Store loads and round-trips it).
//
// Pre-fix: SyncApply promotes the tree in memory (Option B) but writeActive
// fails (prfHash rejects "bogus"), so ConfigPersistDegraded() stays TRUE
// forever (RED). Post-fix the write lands with the supported default.
func TestSyncApply_DormantUnsupportedPRFStaysDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	store := newTestStoreAt(t, path)

	if _, err := store.SyncApply(unappliedGroupUnsupportedPRFText, nil); err != nil {
		t.Fatalf("SyncApply() error = %v", err)
	}

	if store.ConfigPersistDegraded() {
		t.Fatal("ConfigPersistDegraded = true after SyncApply — the dormant unsupported PRF put " +
			"persistence on a deterministic retry loop; the peer's authoritative config never reaches disk (#5638 M30)")
	}

	// The persisted body must be encrypted (a master-password is configured).
	raw, err := os.ReadFile(store.db.activePath())
	if err != nil {
		t.Fatalf("ReadFile(active) error = %v", err)
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatalf("synced config not encrypted (missing envelope marker): %s", string(raw))
	}
	if strings.Contains(string(raw), "dormant-unsupported-fw") {
		t.Fatalf("synced config leaked plaintext host-name to disk: %s", string(raw))
	}

	// Durable across restart: a fresh store at the same path loads the
	// persisted (encrypted) config without error and recovers the host-name.
	reloaded := newTestStoreAt(t, path)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload Load() error = %v (persisted config is not durable)", err)
	}
	active := reloaded.ActiveConfig()
	if active == nil {
		t.Fatal("reloaded ActiveConfig is nil — the synced config did not survive restart")
	}
	if active.System.HostName != "dormant-unsupported-fw" {
		t.Fatalf("reloaded host-name = %q, want %q", active.System.HostName, "dormant-unsupported-fw")
	}
}
