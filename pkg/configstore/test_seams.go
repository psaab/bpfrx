package configstore

// Test-only helpers for configstore.Store. Lives in the production
// package so tests (here and in dependent packages) can inject
// persistence failures without internal-export tricks. Not for
// production callers. Mirrors the pkg/dhcp/test_seams.go convention.

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// SetWriteActiveForTesting overrides active-config persistence
// (#1799). fn(tree) replaces db.WriteActive on every persist path
// (Commit, CommitWithDescription, CommitConfirmed, SyncApply,
// performAutoRollback, Save, and the degraded-persist retry loop).
// Pass nil to restore the real DB write. Callers must not use this
// from production code paths.
func (s *Store) SetWriteActiveForTesting(fn func(*config.ConfigTree) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeActiveFn = fn
}

// SetPersistRetryBackoffForTesting overrides the degraded-persist
// retry loop's initial/max backoff (#1799) so tests can drive the
// loop deterministically with tiny intervals. Must be called BEFORE
// the failure that spawns the retry goroutine. Zero values restore
// the production defaults (1s initial, doubling to a 60s cap).
func (s *Store) SetPersistRetryBackoffForTesting(initial, max time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistRetryInitialBackoff = initial
	s.persistRetryMaxBackoff = max
}
