// Package configstore provides atomic config persistence using JSON files.
package configstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/config"
)

// DB handles atomic persistence of configuration trees to disk.
// It uses write-to-temp + rename for crash safety.
type DB struct {
	dir string
}

// NewDB creates a DB rooted at the given directory.
// The directory is created if it doesn't exist.
func NewDB(dir string) (*DB, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
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

// writeTree persists a config tree to a JSON file atomically.
// Uses write-to-temp + rename for crash safety.
func (db *DB) writeTree(path string, tree *config.ConfigTree) error {
	data, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data, err = db.maybeEncryptTreeJSON(data, tree)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}
