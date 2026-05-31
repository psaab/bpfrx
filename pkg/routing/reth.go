package routing

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// rethManager owns RETH bond cleanup. RETH bonds are no longer created
// (VRRP runs directly on physical member interfaces), so Apply/Names
// are no-ops, but Clear is live: it reaps stale reth* bonds left from
// previous deploys on every config apply.
type rethManager struct {
	ops linkOps
}

// Apply is a no-op. RETH bonds are no longer created; VRRP runs
// directly on physical member interfaces.
func (r *rethManager) Apply(interfaces map[string]*config.InterfaceConfig) error {
	return nil
}

// Clear removes all RETH bond devices from the system. It scans for any
// existing reth* bond devices (including stale ones from previous binary
// versions) and deletes them.
func (r *rethManager) Clear() error {
	// Scan all links for reth* bond devices left from previous deploys.
	links, err := r.ops.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}
	for _, link := range links {
		name := link.Attrs().Name
		if !strings.HasPrefix(name, "reth") {
			continue
		}
		if _, ok := link.(*netlink.Bond); !ok {
			continue // not a bond device
		}
		if err := r.ops.LinkDel(link); err != nil {
			slog.Warn("failed to delete RETH bond", "name", name, "err", err)
		} else {
			slog.Info("RETH bond removed", "name", name)
		}
	}
	return nil
}

// Names returns the names of currently managed RETH interfaces.
// Returns empty since RETH bonds are no longer created.
func (r *rethManager) Names() []string {
	return nil
}
