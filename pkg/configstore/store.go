// Package configstore implements the Junos-style candidate/active
// configuration management with commit and rollback support.
package configstore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// Store manages the candidate and active configuration.
type Store struct {
	mu        sync.RWMutex
	active    *config.ConfigTree
	candidate *config.ConfigTree
	compiled  *config.Config // compiled active config
	history   *History
	dirty     bool
	configDir bool // true if in configuration mode
	filePath  string

	// Commit confirmed state
	confirmTimer    *time.Timer
	confirmPrevTree *config.ConfigTree // active tree before confirmed commit
	confirmPrevCfg  *config.Config     // compiled config before confirmed commit
	autoRollbackFn  func(*config.Config) // callback for dataplane re-apply
}

// New creates a new config store.
func New(filePath string) *Store {
	return &Store{
		active:   &config.ConfigTree{},
		history:  NewHistory(50),
		filePath: filePath,
	}
}

// Load loads the configuration from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // start with empty config
		}
		return fmt.Errorf("read config: %w", err)
	}

	parser := config.NewParser(string(data))
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		return fmt.Errorf("parse config: %s", errs[0].Error())
	}

	compiled, err := config.CompileConfig(tree)
	if err != nil {
		return fmt.Errorf("compile config: %w", err)
	}

	s.active = tree
	s.compiled = compiled
	s.loadRollbackHistory()
	return nil
}

// Save persists the active configuration to disk.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := s.active.Format()
	return os.WriteFile(s.filePath, []byte(data), 0644)
}

// EnterConfigure enters configuration mode by cloning the active config.
// Returns an error if another session is already in config mode.
func (s *Store) EnterConfigure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configDir {
		return fmt.Errorf("configuration is locked by another user")
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	return nil
}

// ExitConfigure exits configuration mode, discarding the candidate.
func (s *Store) ExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = nil
	s.configDir = false
	s.dirty = false
}

// InConfigMode returns true if currently in configuration mode.
func (s *Store) InConfigMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configDir
}

// IsDirty returns true if the candidate differs from active.
func (s *Store) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// Set applies a "set" command to the candidate configuration.
func (s *Store) Set(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.SetPath(path); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// SetFromInput parses a "set ..." command string and applies it.
func (s *Store) SetFromInput(input string) error {
	path, err := config.ParseSetCommand("set " + input)
	if err != nil {
		return err
	}
	return s.Set(path)
}

// Delete removes a node at the given path from the candidate configuration.
func (s *Store) Delete(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.DeletePath(path); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// DeleteFromInput parses a "delete ..." command string and applies it.
func (s *Store) DeleteFromInput(input string) error {
	path, err := config.ParseSetCommand("delete " + input)
	if err != nil {
		return err
	}
	return s.Delete(path)
}

// CommitCheck validates the candidate configuration without applying it.
func (s *Store) CommitCheck() (*config.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := config.CompileConfig(s.candidate)
	if err != nil {
		return nil, err
	}

	return compiled, nil
}

// Commit validates, compiles, and applies the candidate configuration.
// Returns the compiled config for the caller to apply to the dataplane.
func (s *Store) Commit() (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := config.CompileConfig(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	// Push current active to history
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Persist to disk
	data := s.active.Format()
	if s.filePath != "" {
		if err := os.WriteFile(s.filePath, []byte(data), 0644); err != nil {
			// Non-fatal: log but don't fail the commit
			fmt.Fprintf(os.Stderr, "warning: failed to save config: %v\n", err)
		}
		s.saveRollbackFiles()
	}

	return compiled, nil
}

// SetAutoRollbackHandler registers a callback for auto-rollback dataplane re-apply.
func (s *Store) SetAutoRollbackHandler(fn func(*config.Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoRollbackFn = fn
}

// CommitConfirmed validates, compiles, and applies the candidate with an
// automatic rollback timer. If minutes is 0, defaults to 10.
// If a bare "commit" is not issued within the timeout, the config auto-reverts.
func (s *Store) CommitConfirmed(minutes int) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := config.CompileConfig(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	if minutes <= 0 {
		minutes = 10
	}

	// Cancel any existing pending confirmation
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
		s.confirmTimer = nil
	}

	// Save current active state for potential rollback
	s.confirmPrevTree = s.active.Clone()
	s.confirmPrevCfg = s.compiled

	// Push current active to history
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Persist to disk
	data := s.active.Format()
	if s.filePath != "" {
		if err := os.WriteFile(s.filePath, []byte(data), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to save config: %v\n", err)
		}
		s.saveRollbackFiles()
	}

	// Start auto-rollback timer
	s.confirmTimer = time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
		s.performAutoRollback()
	})

	slog.Info("commit confirmed started", "timeout_minutes", minutes)
	return compiled, nil
}

// ConfirmCommit cancels the auto-rollback timer, confirming the config.
func (s *Store) ConfirmCommit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.confirmTimer == nil {
		return fmt.Errorf("no pending confirmed commit")
	}

	s.confirmTimer.Stop()
	s.confirmTimer = nil
	s.confirmPrevTree = nil
	s.confirmPrevCfg = nil

	slog.Info("commit confirmed")
	return nil
}

// IsConfirmPending returns true if a commit confirmed is awaiting confirmation.
func (s *Store) IsConfirmPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmTimer != nil
}

// performAutoRollback reverts the active config to the saved pre-confirmed state.
func (s *Store) performAutoRollback() {
	s.mu.Lock()

	if s.confirmPrevTree == nil {
		s.mu.Unlock()
		return
	}

	s.active = s.confirmPrevTree
	s.compiled = s.confirmPrevCfg
	if s.candidate != nil {
		s.candidate = s.active.Clone()
	}
	s.dirty = false

	s.confirmTimer = nil
	s.confirmPrevTree = nil
	prevCfg := s.confirmPrevCfg
	s.confirmPrevCfg = nil

	// Persist reverted config to disk
	if s.filePath != "" {
		data := s.active.Format()
		if err := os.WriteFile(s.filePath, []byte(data), 0644); err != nil {
			slog.Warn("failed to save reverted config", "err", err)
		}
	}

	fn := s.autoRollbackFn
	s.mu.Unlock()

	slog.Warn("commit confirmed timed out, configuration rolled back")

	// Call dataplane re-apply outside the lock
	if fn != nil && prevCfg != nil {
		fn(prevCfg)
	}
}

// Rollback reverts the candidate to a previous configuration.
// n=0 reverts to active; n>0 reverts to the nth previous commit.
func (s *Store) Rollback(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if n == 0 {
		s.candidate = s.active.Clone()
		s.dirty = false
		return nil
	}

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return err
	}
	s.candidate = entry.Config.Clone()
	s.dirty = true
	return nil
}

// ShowCandidate returns the candidate configuration as hierarchical text.
func (s *Store) ShowCandidate() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.Format()
	}
	return ""
}

// ShowActive returns the active configuration as hierarchical text.
func (s *Store) ShowActive() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Format()
}

// ShowCandidateSet returns the candidate configuration as flat set commands.
func (s *Store) ShowCandidateSet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatSet()
	}
	return ""
}

// ActiveConfig returns the compiled active configuration.
func (s *Store) ActiveConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.compiled
}

// ExportJSON exports the active config as JSON (for debugging).
func (s *Store) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s.compiled, "", "  ")
}

// ListHistory returns all history entries, most recent first (goroutine-safe).
func (s *Store) ListHistory() []*HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.history.List()
}

// rollbackPath returns the file path for rollback slot n (1-based).
func (s *Store) rollbackPath(n int) string {
	return filepath.Join(filepath.Dir(s.filePath), fmt.Sprintf("%s.%d", filepath.Base(s.filePath), n))
}

// saveRollbackFiles writes rollback history entries to numbered files.
// Must be called under write lock.
func (s *Store) saveRollbackFiles() {
	if s.filePath == "" {
		return
	}

	entries := s.history.List() // most-recent-first
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			slog.Warn("failed to write rollback file", "path", path, "err", err)
		}
	}
	s.cleanupRollbackFiles(len(entries) + 1)
}

// cleanupRollbackFiles removes stale rollback files starting from startIdx.
func (s *Store) cleanupRollbackFiles(startIdx int) {
	for i := startIdx; i <= s.history.MaxSize()+1; i++ {
		path := s.rollbackPath(i)
		if err := os.Remove(path); err != nil {
			break // stop on first not-found (contiguous sequence)
		}
	}
}

// loadRollbackHistory reads numbered rollback files and populates the history.
// Must be called under write lock.
func (s *Store) loadRollbackHistory() {
	if s.filePath == "" {
		return
	}

	var entries []*HistoryEntry
	for i := 1; i <= s.history.MaxSize(); i++ {
		path := s.rollbackPath(i)
		data, err := os.ReadFile(path)
		if err != nil {
			break // stop on first not-found
		}
		parser := config.NewParser(string(data))
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			slog.Warn("skipping corrupt rollback file", "path", path, "err", errs[0])
			continue
		}
		// Use file modification time as timestamp
		info, _ := os.Stat(path)
		ts := time.Now()
		if info != nil {
			ts = info.ModTime()
		}
		entries = append(entries, &HistoryEntry{
			Config:    tree,
			Timestamp: ts,
		})
	}

	// Push oldest-first so History ordering is correct
	for i := len(entries) - 1; i >= 0; i-- {
		s.history.Push(entries[i])
	}

	if len(entries) > 0 {
		slog.Info("loaded rollback history", "entries", len(entries))
	}
}

// ShowActiveSet returns the active configuration as flat set commands.
func (s *Store) ShowActiveSet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatSet()
}

// ShowRollback returns the content of rollback slot n (1-based) as hierarchical text.
func (s *Store) ShowRollback(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}
	return entry.Config.Format(), nil
}

// ShowRollbackSet returns the content of rollback slot n (1-based) as flat set commands.
func (s *Store) ShowRollbackSet(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}
	return entry.Config.FormatSet(), nil
}

// ShowCompareRollback returns a diff between rollback slot n and the candidate.
func (s *Store) ShowCompareRollback(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return "", fmt.Errorf("not in configuration mode")
	}

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}

	rollbackSet := entry.Config.FormatSet()
	candidateSet := s.candidate.FormatSet()

	rollbackLines := splitLines(rollbackSet)
	candidateLines := splitLines(candidateSet)

	rollbackMap := make(map[string]bool, len(rollbackLines))
	for _, line := range rollbackLines {
		rollbackMap[line] = true
	}
	candidateMap := make(map[string]bool, len(candidateLines))
	for _, line := range candidateLines {
		candidateMap[line] = true
	}

	var b strings.Builder

	for _, line := range rollbackLines {
		if !candidateMap[line] {
			fmt.Fprintf(&b, "- %s\n", line)
		}
	}
	for _, line := range candidateLines {
		if !rollbackMap[line] {
			fmt.Fprintf(&b, "+ %s\n", line)
		}
	}

	if b.Len() == 0 {
		return "[no changes]\n", nil
	}
	return b.String(), nil
}

// ShowCompare returns a diff between the active and candidate configurations
// as set commands, with "-" for removed lines and "+" for added lines.
func (s *Store) ShowCompare() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	activeSet := s.active.FormatSet()
	candidateSet := s.candidate.FormatSet()

	activeLines := splitLines(activeSet)
	candidateLines := splitLines(candidateSet)

	// Build sets for O(n) diff
	activeMap := make(map[string]bool, len(activeLines))
	for _, line := range activeLines {
		activeMap[line] = true
	}
	candidateMap := make(map[string]bool, len(candidateLines))
	for _, line := range candidateLines {
		candidateMap[line] = true
	}

	var b strings.Builder

	// Removed lines (in active but not candidate)
	for _, line := range activeLines {
		if !candidateMap[line] {
			fmt.Fprintf(&b, "- %s\n", line)
		}
	}

	// Added lines (in candidate but not active)
	for _, line := range candidateLines {
		if !activeMap[line] {
			fmt.Fprintf(&b, "+ %s\n", line)
		}
	}

	if b.Len() == 0 {
		return "[no changes]\n"
	}
	return b.String()
}

// splitLines splits a string into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
