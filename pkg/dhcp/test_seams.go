package dhcp

// Test-only helpers for pkg/dhcp.Manager. Lives in the production
// package so external packages (e.g. pkg/api tests) can use these
// without internal-export tricks. Not for production callers.

// SeedLeaseForTesting installs a lease record for tests. Callers
// must not use this from production code paths.
func (m *Manager) SeedLeaseForTesting(ifaceName string, af AddressFamily, lease *Lease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leases == nil {
		m.leases = make(map[clientKey]*Lease)
	}
	m.leases[clientKey{iface: ifaceName, family: af}] = lease
}
