// Package configstore provides atomic config persistence using JSON files.
package configstore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// DB handles durable persistence of configuration trees to disk.
// Writes go through fsatomic.WriteFileDurable (#1894): temp + fsync +
// rename + dir fsync, so a persisted tree survives power loss.
type DB struct {
	dir string

	// writerVersion is the xpf build version stamped into the config
	// compatibility-envelope header on write (#1917 increment B, plan
	// §6.4 / D1). Empty => "unknown". Set via SetWriterVersion from the
	// daemon's ldflags version before the first write.
	writerVersion string
}

// SetWriterVersion sets the build version stamped into the config-DB
// compatibility envelope on write (#1917). Call once at startup before
// any WriteActive; the daemon's single init path is the only caller.
func (db *DB) SetWriterVersion(v string) {
	db.writerVersion = v
}

// NewDB creates a DB rooted at the given directory.
// The directory is created if it doesn't exist.
func NewDB(dir string) (*DB, error) {
	// Durable creation (#1894 code-r1): on first boot the .configdb
	// entry itself must survive power loss, or a commit that reported
	// success can vanish with the whole directory. WriteFileDurable
	// only fsyncs .configdb (the file's parent), not /etc/xpf.
	//
	// Owner-only 0700 (#4056): this directory holds master.key plus the
	// active/candidate/rollback config DB — every file that may carry a
	// cleartext IKE PSK / auth key when master-password is not set. It is
	// a dedicated, xpf-owned subdirectory, so 0700 leaks nothing an
	// operator needs. The FILES themselves are 0600 (writeTreeMarked); the
	// dir mode is defense-in-depth so a non-owner cannot even enumerate
	// the slot names.
	if err := fsatomic.MkdirAllDurable(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	// MkdirAllDurable does not chmod an already-existing directory, so an
	// upgrade from a pre-#4056 build inherits the old 0755. Enforce 0700
	// here — the daemon owns the dir, so this is idempotent and cheap.
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("restrict db dir perms: %w", err)
	}
	// Sweep temp files leaked by a crash mid-write (#1894). fsatomic
	// names its temps ".<base>.tmp-<random>", so a daemon killed between
	// CreateTemp and rename leaves one behind; they are dead weight and
	// would accumulate forever in a long-lived .configdb.
	if stale, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*")); err == nil {
		for _, p := range stale {
			_ = os.Remove(p)
		}
	}
	return &DB{dir: dir}, nil
}

// activePath returns the path to the active config file.
func (db *DB) activePath() string {
	return filepath.Join(db.dir, "active.json")
}

// candidatePath returns the path to the candidate config file.
func (db *DB) candidatePath() string {
	return filepath.Join(db.dir, "candidate.json")
}

// rollbackPath returns the path for rollback slot n (1-based).
func (db *DB) rollbackPath(n int) string {
	return filepath.Join(db.dir, fmt.Sprintf("rollback.%d.json", n))
}

// ReadActive loads the active configuration from disk.
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadActive() (*config.ConfigTree, error) {
	tree, _, err := db.readTreeMeta(db.activePath())
	return tree, err
}

// ReadActiveMeta loads the active configuration AND the #1922 step-0
// committed marker. committed is TRUE when the file is absent (no marker to
// honor — Load treats absent as start-fresh anyway), TRUE for a legacy
// (no-envelope) DB, and TRUE for any enveloped DB that omits or sets
// committed=1; it is FALSE only for an enveloped DB this build wrote with
// the explicit never-committed marker (committed=0).
func (db *DB) ReadActiveMeta() (tree *config.ConfigTree, committed bool, err error) {
	return db.readTreeMeta(db.activePath())
}

// WriteActive persists the active configuration to disk atomically. The
// on-disk envelope is stamped committed=1 (a real successful commit/sync).
func (db *DB) WriteActive(tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.activePath(), tree, true)
}

// WriteActiveMarker persists tree as the active config with an explicit
// #1922 step-0 committed marker. committed=false writes the never-committed
// marker used by the Item 1b first-commit rollback (enterBootstrapMode):
// the empty tree on disk must NOT later classify as operator-committed-empty.
func (db *DB) WriteActiveMarker(tree *config.ConfigTree, committed bool) error {
	return db.writeTreeMarked(db.activePath(), tree, committed)
}

// ReadCandidate loads the candidate configuration from disk.
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadCandidate() (*config.ConfigTree, error) {
	tree, _, err := db.readTreeMeta(db.candidatePath())
	return tree, err
}

// WriteCandidate persists the candidate configuration to disk atomically.
func (db *DB) WriteCandidate(tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.candidatePath(), tree, true)
}

// DeleteCandidate removes the candidate file from disk.
func (db *DB) DeleteCandidate() error {
	err := os.Remove(db.candidatePath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete candidate: %w", err)
	}
	return nil
}

// ReadRollback loads a rollback configuration from slot n (1-based).
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadRollback(n int) (*config.ConfigTree, error) {
	tree, _, err := db.readTreeMeta(db.rollbackPath(n))
	return tree, err
}

// WriteRollback persists a rollback configuration to slot n (1-based).
func (db *DB) WriteRollback(n int, tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.rollbackPath(n), tree, true)
}

// DeleteRollback removes rollback slot n from disk.
func (db *DB) DeleteRollback(n int) error {
	err := os.Remove(db.rollbackPath(n))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete rollback %d: %w", n, err)
	}
	return nil
}

// confirmRecord is the persisted pending commit-confirmed state (#4577). It
// survives a daemon crash/reboot INSIDE the confirm window so the
// auto-rollback safety hatch is not silently lost: the in-memory
// time.AfterFunc rollback timer does not outlive the process, so without this
// record a crash before the operator confirms would make an UNCONFIRMED config
// permanent (the classic management-stranding trap). Store.Load re-arms the
// timer when the deadline is still in the future, or rolls back to PrevTree
// when it already passed during downtime.
type confirmRecord struct {
	// Deadline is the absolute wall-clock time the confirm window expires.
	Deadline time.Time `json:"deadline"`
	// PrevTree is the rollback target — the config that was active BEFORE the
	// still-unconfirmed commit-confirmed. For a NESTED confirmed commit it
	// stays the ORIGINAL last-confirmed config (mirrors confirmPrevTree).
	PrevTree *config.ConfigTree `json:"prev_tree"`
	// FirstCommit records that PrevTree is the empty bootstrap tree (the
	// commit-confirmed was the first commit on a fresh store, confirmPrevCfg
	// was nil at arm time). The rollback must then re-enter never-committed
	// state (committed=0 marker), matching the in-memory PromoteRollback
	// #1922 Item 1b path — not persist an operator-committed-empty config.
	FirstCommit bool `json:"first_commit"`
}

// confirmPath returns the path to the pending commit-confirmed state file.
func (db *DB) confirmPath() string {
	return filepath.Join(db.dir, "confirm.json")
}

// WriteConfirm persists the pending commit-confirmed state durably (#4577):
// temp + fsync + rename + dir fsync, so the deadline+rollback-target survive
// power loss. The embedded PrevTree may carry secret leaves (IKE PSK, auth
// keys), so it is encrypted with the same master-password machinery as
// active.json (keyed off the prev tree's master-password leaf) and written
// owner-only 0600. No #1917 compatibility envelope is used — the file is
// transient recovery state, not a committed config, and confirmRecord evolves
// via additive JSON fields.
func (db *DB) WriteConfirm(rec *confirmRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal confirm state: %w", err)
	}
	data, err = db.maybeEncryptTreeJSON(data, rec.PrevTree)
	if err != nil {
		return fmt.Errorf("encrypt confirm state: %w", err)
	}
	if err := fsatomic.WriteFileDurable(db.confirmPath(), data, 0600); err != nil {
		return fmt.Errorf("persist confirm state: %w", err)
	}
	return nil
}

// ReadConfirm loads the pending commit-confirmed state, or (nil, nil) if none
// is persisted (#4577).
func (db *DB) ReadConfirm() (*confirmRecord, error) {
	data, err := os.ReadFile(db.confirmPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read confirm state: %w", err)
	}
	data, _, err = db.maybeDecryptTreeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt confirm state: %w", err)
	}
	rec := &confirmRecord{}
	if err := json.Unmarshal(data, rec); err != nil {
		return nil, fmt.Errorf("parse confirm state: %w", err)
	}
	return rec, nil
}

// DeleteConfirm removes the pending commit-confirmed state file (#4577).
// Absent is not an error.
//
// The removal is a DURABLE transition (#4864): after a successful unlink the
// parent directory is fsynced so the directory-entry removal survives a
// crash/power-loss. WriteConfirm persists confirm.json through
// fsatomic.WriteFileDurable (temp + fsync + rename + dir fsync); without a
// matching dir fsync here a *successful* unlink is not durable, so a crash in
// the window before the dirent flushes can replay the stale confirm.json on
// reboot — and recoverPendingConfirmLocked would then revert an
// already-confirmed config (re-diverging a confirmed HA standby). The unlink
// and dir fsync route through the package durability seams (rbRemove/rbSyncDir,
// #3441) so a downgrade that drops the dir sync fails a test RED.
func (db *DB) DeleteConfirm() error {
	if err := rbRemove(db.confirmPath()); err != nil {
		if os.IsNotExist(err) {
			// Already absent: nothing was unlinked, so no dir sync is needed.
			return nil
		}
		return fmt.Errorf("delete confirm state: %w", err)
	}
	if err := rbSyncDir(filepath.Dir(db.confirmPath())); err != nil {
		return fmt.Errorf("sync dir after delete confirm state: %w", err)
	}
	return nil
}

// readTreeMeta reads and parses a config tree from a JSON file, returning
// the #1922 step-0 committed marker alongside it. Returns (nil, true, nil)
// if the file doesn't exist (absent => start-fresh; committed is irrelevant
// but defaults true so an absent-DB caller never sees a spurious
// never-committed signal). A legacy (no-envelope) DB also reads committed.
func (db *DB) readTreeMeta(path string) (*config.ConfigTree, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, true, nil
		}
		return nil, true, fmt.Errorf("read %s: %w", path, err)
	}
	// Config compatibility envelope (#1917 increment B). The envelope is
	// the OUTERMOST framing — a magic header line prepended to the
	// (possibly-encrypted) body. Strip+validate it BEFORE decryption so a
	// too-new DB fails closed here, never silently empty-loads. A body
	// with no envelope is a pre-floor (legacy) DB and is read unchanged
	// (committed defaults true — migration rule C3).
	committed := true
	if hasEnvelope(data) {
		body, hdr, eerr := stripEnvelope(data)
		if eerr != nil {
			return nil, true, fmt.Errorf("read %s: %w", path, eerr)
		}
		data = body
		committed = hdr.Committed
	}

	data, decrypted, err := db.maybeDecryptTreeJSON(data)
	if err != nil {
		return nil, true, fmt.Errorf("decrypt %s: %w", path, err)
	}

	tree := &config.ConfigTree{}
	if err := json.Unmarshal(data, tree); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", path, err)
	}

	// Unexpected-plaintext warning (#4579 A4-06). When master-password is
	// set, every write path encrypts the body (maybeEncryptTreeJSON keyed
	// off the tree's master-password leaf), so a config that DECLARES a
	// master-password should never be read back as plaintext. If it is,
	// the file was written without the AES-GCM envelope — a downgrade to
	// an older build, a restore from an unencrypted backup, or tampering.
	// Reaching this state needs write access to the 0600/0700 .configdb
	// (root/owner), so it is not a privilege-escalation vector; the warn
	// makes the silent at-rest exposure visible instead of loading the
	// cleartext secrets without a trace. Boot-time / commit-paced read, so
	// a one-time slog.Warn is safe (never in a per-packet/-session loop).
	if !decrypted && masterPasswordPRF(tree) != "" {
		slog.Warn("configuration declares a master-password but was read as "+
			"UNENCRYPTED plaintext (expected an AES-GCM envelope) — the config "+
			"may have been downgraded, restored from an unencrypted backup, or "+
			"tampered with; secrets are exposed at rest",
			"path", path, "issue", "#4579")
	}
	return tree, committed, nil
}

// writeTree persists a config tree to a JSON file durably (#1894,
// DurableState class): temp + fsync + rename + dir fsync, so a commit
// that reported success cannot be silently lost to a power cut — the
// guarantee the #1799 persist-before-promote contract is built on.
func (db *DB) writeTreeMarked(path string, tree *config.ConfigTree, committed bool) error {
	data, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data, err = db.maybeEncryptTreeJSON(data, tree)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	// Wrap the (possibly-encrypted) body in the config compatibility
	// envelope (#1917 increment B). The magic header line makes a pre-floor
	// reader fail closed (its json.Unmarshal rejects a leading '#'), so a
	// future format bump can never silently empty-load on an old reader.
	// committed stamps the #1922 step-0 marker.
	data = wrapEnvelope(data, db.writerVersion, committed)

	// Owner-only 0600 (#4056): active.json / candidate.json /
	// rollback.N.json carry the full config, including secret leaves (IKE
	// PSK, WireGuard/auth keys, SNMP community). When master-password is
	// set the body is AES-GCM encrypted, but when it is not the secrets are
	// cleartext — either way the DB must not be world-readable. The daemon
	// runs as the owner, so 0600 does not affect read-back.
	if err := fsatomic.WriteFileDurable(path, data, 0600); err != nil {
		return fmt.Errorf("persist %s: %w", path, err)
	}
	return nil
}
