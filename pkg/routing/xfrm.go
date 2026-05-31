package routing

import (
	"log/slog"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// xfrmManager owns XFRM virtual interface (xfrmi) lifecycle for IPsec
// VPN tunnels. The mu field replaces the xfrmis slice of the former
// shared Manager.ifaceMu.
type xfrmManager struct {
	ops linkOps

	mu     sync.Mutex
	xfrmis []string // currently created xfrmi interface names
}

// Apply creates XFRM virtual interfaces for IPsec VPN tunnels. Each VPN
// with a BindInterface (e.g. "st0.0") gets a unit-specific xfrmi device
// and a stable XFRM interface ID derived from the st/unit pair.
func (x *xfrmManager) Apply(vpns map[string]*config.IPsecVPN) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.clearLocked(); err != nil {
		slog.Warn("failed to clear previous xfrmi interfaces", "err", err)
	}

	for _, vpn := range vpns {
		if vpn.BindInterface == "" {
			continue
		}

		ifName, ifID := config.XFRMIfNameAndID(vpn.BindInterface)
		if ifName == "" || ifID == 0 {
			slog.Warn("invalid bind-interface name",
				"vpn", vpn.Name, "bind-interface", vpn.BindInterface)
			continue
		}

		// Check if already exists
		if link, err := x.ops.LinkByName(ifName); err == nil {
			x.ops.LinkSetUp(link)
			slog.Debug("xfrmi already exists", "name", ifName, "if_id", ifID)
			// Track if not already tracked
			found := false
			for _, xi := range x.xfrmis {
				if xi == ifName {
					found = true
					break
				}
			}
			if !found {
				x.xfrmis = append(x.xfrmis, ifName)
			}
			continue
		}

		xfrmi := &netlink.Xfrmi{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
			Ifid: ifID,
		}

		if err := x.ops.LinkAdd(xfrmi); err != nil {
			slog.Warn("failed to create xfrmi",
				"name", ifName, "if_id", ifID, "err", err)
			continue
		}

		link, err := x.ops.LinkByName(ifName)
		if err != nil {
			slog.Warn("failed to find xfrmi after creation",
				"name", ifName, "err", err)
			continue
		}

		if err := x.ops.LinkSetUp(link); err != nil {
			slog.Warn("failed to bring up xfrmi",
				"name", ifName, "err", err)
		}

		slog.Info("xfrmi created", "name", ifName, "if_id", ifID, "vpn", vpn.Name)
		x.xfrmis = append(x.xfrmis, ifName)
	}

	return nil
}

// Clear removes all previously created xfrmi interfaces.
func (x *xfrmManager) Clear() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.clearLocked()
}

// clearLocked is the lock-free body of Clear. Caller must hold mu.
// Used internally by Apply.
func (x *xfrmManager) clearLocked() error {
	for _, name := range x.xfrmis {
		link, err := x.ops.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := x.ops.LinkDel(link); err != nil {
			slog.Warn("failed to delete xfrmi", "name", name, "err", err)
		} else {
			slog.Info("xfrmi removed", "name", name)
		}
	}
	x.xfrmis = nil
	return nil
}
