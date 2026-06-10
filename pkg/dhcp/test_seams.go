package dhcp

import (
	"context"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

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

// NewManagerForTesting builds a Manager without a netlink handle and
// with the per-client run goroutine replaced by runClient, so reconcile
// and registry behavior can be tested without real DHCP traffic or
// netlink access. runClient should block on ctx.Done() to model a
// long-running client, or return early to model a terminal exit.
func NewManagerForTesting(runClient func(ctx context.Context, ifaceName string, af AddressFamily)) *Manager {
	return &Manager{
		clients:          make(map[clientKey]*dhcpClient),
		leases:           make(map[clientKey]*Lease),
		delegatedPDs:     make(map[string][]DelegatedPrefix),
		duids:            make(map[string]dhcpv6.DUID),
		duidTypes:        make(map[string]string),
		v4opts:           make(map[string]*DHCPv4Options),
		v6opts:           make(map[string]*DHCPv6Options),
		runClientForTest: runClient,
	}
}

// RunningClientHandlesForTesting returns an opaque handle per running
// client keyed "iface/4" or "iface/6". Handles compare equal across
// calls iff the same client goroutine is still registered — tests use
// this to assert a reconcile did (or did not) restart a client.
func (m *Manager) RunningClientHandlesForTesting() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]any, len(m.clients))
	for k, dc := range m.clients {
		out[fmt.Sprintf("%s/%d", k.iface, k.family)] = dc
	}
	return out
}
