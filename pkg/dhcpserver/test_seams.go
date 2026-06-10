package dhcpserver

import "log/slog"

// Test-only helpers for pkg/dhcpserver.Manager, following the
// pkg/dhcp/test_seams.go convention: they live in the production
// package so tests (here and in other packages) can build managers
// without shelling out to systemctl or writing under /etc/kea. Not
// for production callers.

// NewManagerForTesting builds a Manager with injectable systemctl
// seams and config file paths.
//
//   - confPath4/confPath6: where generated Kea configs are written
//     (tests pass t.TempDir() paths).
//   - runSystemctl: replaces the real `systemctl <args...>` shell-out
//     (restart/stop). Return nil for success.
//   - unitActive: replaces the `systemctl is-active <unit>` query used
//     for authoritative reconcile (#1778).
func NewManagerForTesting(
	confPath4, confPath6 string,
	runSystemctl func(args ...string) error,
	unitActive func(unit string) bool,
) *Manager {
	return &Manager{
		confPath4:    confPath4,
		confPath6:    confPath6,
		runSystemctl: runSystemctl,
		unitActive:   unitActive,
		warn:         slog.Warn,
	}
}

// SetWarnForTesting replaces the manager's warning sink (default
// slog.Warn) so tests can assert that generate-time configuration
// warnings — e.g. ambiguous Kea subnet selection (#1835 F1) — fire.
func (m *Manager) SetWarnForTesting(fn func(msg string, args ...any)) {
	m.warn = fn
}
