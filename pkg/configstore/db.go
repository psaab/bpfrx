// Package configstore provides atomic config persistence using JSON files.
package configstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	if err := fsatomic.MkdirAllDurable(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
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
	return db.readTree(db.activePath())
}

// WriteActive persists the active configuration to disk atomically.
func (db *DB) WriteActive(tree *config.ConfigTree) error {
	return db.writeTree(db.activePath(), tree)
}

// ReadCandidate loads the candidate configuration from disk.
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadCandidate() (*config.ConfigTree, error) {
	return db.readTree(db.candidatePath())
}

// WriteCandidate persists the candidate configuration to disk atomically.
func (db *DB) WriteCandidate(tree *config.ConfigTree) error {
	return db.writeTree(db.candidatePath(), tree)
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
	return db.readTree(db.rollbackPath(n))
}

// WriteRollback persists a rollback configuration to slot n (1-based).
func (db *DB) WriteRollback(n int, tree *config.ConfigTree) error {
	return db.writeTree(db.rollbackPath(n), tree)
}

// DeleteRollback removes rollback slot n from disk.
func (db *DB) DeleteRollback(n int) error {
	err := os.Remove(db.rollbackPath(n))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete rollback %d: %w", n, err)
	}
	return nil
}

// readTree reads and parses a config tree from a JSON file.
// Returns (nil, nil) if the file doesn't exist.
func (db *DB) readTree(path string) (*config.ConfigTree, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Config compatibility envelope (#1917 increment B). The envelope is
	// the OUTERMOST framing — a magic header line prepended to the
	// (possibly-encrypted) body. Strip+validate it BEFORE decryption so a
	// too-new DB fails closed here, never silently empty-loads. A body
	// with no envelope is a pre-floor (legacy) DB and is read unchanged.
	if hasEnvelope(data) {
		body, _, eerr := stripEnvelope(data)
		if eerr != nil {
			return nil, fmt.Errorf("read %s: %w", path, eerr)
		}
		data = body
	}

	data, err = db.maybeDecryptTreeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}

	tree := &config.ConfigTree{}
	if err := json.Unmarshal(data, tree); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return tree, nil
}

// writeTree persists a config tree to a JSON file durably (#1894,
// DurableState class): temp + fsync + rename + dir fsync, so a commit
// that reported success cannot be silently lost to a power cut — the
// guarantee the #1799 persist-before-promote contract is built on.
func (db *DB) writeTree(path string, tree *config.ConfigTree) error {
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
	data = wrapEnvelope(data, db.writerVersion)

	if err := fsatomic.WriteFileDurable(path, data, 0644); err != nil {
		return fmt.Errorf("persist %s: %w", path, err)
	}
	return nil
}
