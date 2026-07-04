package configstore

import (
	"fmt"
	"log/slog"
	"time"
)

// ensureWritableLocked returns ErrClusterReadOnly when the store is in
// cluster read-only mode (a non-RG0-primary / secondary node; config
// authority is the primary). Callers MUST hold s.mu.
//
// #3893: the read-only flag was previously checked ONLY at the
// EnterConfigure* gate. Once a config session was already open (entered
// before the node became secondary, or via a path that did not re-check),
// Set/Delete/Commit/Load/Rollback only verified candidate!=nil — so an open
// session could Set+Commit on the read-only secondary and diverge its active
// config from the primary (the local edit is one the primary never sees and
// the next config-sync overwrites, causing churn). Every user-session
// mutating op now calls this helper so the mutation is rejected regardless of
// when the session was opened. The internal HA-sync ingress (SyncApply) and
// the commit-confirmed timeout revert (PromoteRollback) do NOT go through the
// gated methods, so they correctly bypass this gate.
func (s *Store) ensureWritableLocked() error {
	if s.clusterReadOnly {
		return ErrClusterReadOnly
	}
	return nil
}

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
	if err := s.ensureWritableLocked(); err != nil {
		return err
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
	if err := s.ensureWritableLocked(); err != nil {
		return err
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

// effectiveHolderLocked returns the session ID that currently holds the config
// lock, regardless of mode. Exclusive mode records the holder in
// exclusiveHolder; shared/private mode records it in configHolder. Callers MUST
// hold s.mu. Returns "" when no session identifier was supplied at acquire time
// (the internal EnterConfigure()/daemon path) or when unlocked.
func (s *Store) effectiveHolderLocked() string {
	if s.exclusiveHolder != "" {
		return s.exclusiveHolder
	}
	return s.configHolder
}

// ExitConfigureSession exits configuration mode only if the given session holds
// the lock. Returns true if the lock was released.
//
// #3979: the release guard must match against whichever holder field the
// acquiring mode actually set. EnterConfigureExclusive records the holder in
// exclusiveHolder and leaves configHolder empty; the previous guard compared
// only configHolder, so an exclusive holder could NEVER release its own lock —
// the guard saw configHolder("") != sessionID and bailed out early. The lock
// then persisted with no live holder (the disconnect auto-release in
// configLockInterceptor routes through here too, so it silently failed), and
// every subsequent configure/configure exclusive/configure private was
// rejected until daemon restart — a single operator using `configure exclusive`
// then disconnecting bricked all future config edits. Comparing against the
// effective holder releases whichever lock THIS session holds and restores the
// stale-holder reclaim on disconnect.
func (s *Store) ExitConfigureSession(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return false
	}
	if sessionID != "" && s.effectiveHolderLocked() != sessionID {
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
// and whether the lock is held. #3979: report the effective holder so an
// exclusive lock (tracked in exclusiveHolder, with configHolder empty) is
// attributed to its real holder in `clear system config-lock` / diagnostic
// output instead of an empty string.
func (s *Store) ConfigHolder() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.effectiveHolderLocked(), s.configDir
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
