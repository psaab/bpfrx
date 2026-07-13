package routing

import (
	"errors"
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
//
// A per-bond LinkDel failure is aggregated with errors.Join and returned,
// not swallowed: a stale reth* bond that could not be torn down (EBUSY /
// EPERM / transient netlink error) leaves stale host RETH ownership — and
// potentially stale VIP/MAC state — in the kernel while the daemon believes
// the teardown succeeded (a fail-open reported as success, codex-review-182
// M30 / #5704, the reth analog of the #4901 xfrm/bond/tunnel Clear fix and
// the #5310/#5703 fail-closed discipline). Surfacing the error fails the
// commit closed. Retry is implicit: Clear re-scans LinkList every apply, so
// a bond whose delete failed is rediscovered and re-attempted next reconcile
// (there is no ownership map to retain, unlike xfrm/bond/tunnel). Idempotence
// is preserved: an already-absent reth device is simply not returned by
// LinkList, so no LinkDel is attempted and no spurious error is produced.
func (r *rethManager) Clear() error {
	// Scan all links for reth* bond devices left from previous deploys.
	links, err := r.ops.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}
	var errs []error
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
			errs = append(errs, fmt.Errorf("deleting RETH bond %s: %w", name, err))
		} else {
			slog.Info("RETH bond removed", "name", name)
		}
	}
	return errors.Join(errs...)
}

// Names returns the names of currently managed RETH interfaces.
// Returns empty since RETH bonds are no longer created.
func (r *rethManager) Names() []string {
	return nil
}
