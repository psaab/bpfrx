package configstore

import (
	"fmt"
	"log/slog"
	"time"
)

// EnterConfigure enters configuration mode by cloning the active config.
// Returns an error if another session is already in config mode.
func (s *Store) EnterConfigure() error {
	return s.EnterConfigureSession("")
}

// EnterConfigureSession enters configuration mode with a session identifier.
// If the same session already holds the lock, it's a no-op.
func (s *Store) EnterConfigureSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterReadOnly {
		return fmt.Errorf("configuration database is not writable (secondary node)")
	}
	if s.configDir {
		// Allow re-entry by same session.
		if sessionID != "" && s.configHolder == sessionID {
			return nil
		}
		// #2157: return the ErrConfigLocked sentinel (wrapping the plain
		// message) so deferrable callers (the event-options action worker)
		// can errors.Is it and retry instead of string-matching.
		return fmt.Errorf("%w", ErrConfigLocked)
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.configHolder = sessionID
	s.configLockAt = time.Now()
	return nil
}

// EnterConfigureExclusive enters exclusive configuration mode.
func (s *Store) EnterConfigureExclusive(holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterReadOnly {
		return fmt.Errorf("configuration database is not writable (secondary node)")
	}
	if s.configDir {
		return fmt.Errorf("%w", ErrConfigLocked)
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.exclusiveHolder = holder
	s.configLockAt = time.Now()
	return nil
}

// ExitConfigureSession exits configuration mode only if the given session holds
// the lock. Returns true if the lock was released.
func (s *Store) ExitConfigureSession(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return false
	}
	if sessionID != "" && s.configHolder != sessionID {
		return false
	}
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	s.editPath = nil
	return true
}

// ForceExitConfigure exits configuration mode regardless of who holds the lock.
// Used for stale lock cleanup.
func (s *Store) ForceExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return
	}
	slog.Warn("force-releasing stale config lock", "holder", s.configHolder,
		"held_for", time.Since(s.configLockAt).Round(time.Second))
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	s.editPath = nil
}

// ConfigHolder returns the session ID of the current config lock holder
// and whether the lock is held.
func (s *Store) ConfigHolder() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configHolder, s.configDir
}

// IsExclusiveLocked returns true if exclusive mode is active.
func (s *Store) IsExclusiveLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exclusiveHolder != ""
}

// ExitConfigure exits configuration mode, discarding the candidate.
func (s *Store) ExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.editPath = nil
}

// SetEditPath sets the edit path for hierarchical navigation.
func (s *Store) SetEditPath(path []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = path
}

// GetEditPath returns a copy of the current edit path.
func (s *Store) GetEditPath() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.editPath...)
}

// NavigateUp moves the edit path up one level.
func (s *Store) NavigateUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.editPath) > 0 {
		s.editPath = s.editPath[:len(s.editPath)-1]
	}
}

// NavigateTop resets the edit path to the root.
func (s *Store) NavigateTop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = nil
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
