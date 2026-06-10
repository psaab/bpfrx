package configstore

// Test-only helpers for configstore.Store. Lives in the production
// package so tests (here and in dependent packages) can inject
// persistence failures without internal-export tricks. Not for
// production callers. Mirrors the pkg/dhcp/test_seams.go convention.

import (
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
