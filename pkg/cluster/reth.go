// Package cluster RETH (Redundant Ethernet) failover management.
// Controls active/passive bond members based on redundancy group state.
package cluster

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

// RethMapping maps a RETH interface to its redundancy group.
type RethMapping struct {
	RethName      string
	RedundancyGrp int
	Members       []string // physical member interface names
}

// RethController manages RETH bond member activation/deactivation
// based on cluster redundancy group state transitions.
type RethController struct {
	nlHandle *netlink.Handle
	mappings []RethMapping
	mu       sync.Mutex
}

// NewRethController creates a RETH failover controller.
func NewRethController() (*RethController, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("reth controller netlink: %w", err)
	}
	return &RethController{nlHandle: h}, nil
}

// Close releases resources.
func (rc *RethController) Close() {
	if rc.nlHandle != nil {
		rc.nlHandle.Close()
	}
}

// SetMappings updates the RETH-to-RG mappings.
func (rc *RethController) SetMappings(mappings []RethMapping) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.mappings = mappings
}

// HandleStateChange processes a cluster state change event.
// Bonds are always kept UP on both nodes so that VRRP can send
// advertisements on both primary and secondary. VRRP handles VIP placement.
func (rc *RethController) HandleStateChange(event ClusterEvent) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, m := range rc.mappings {
		if m.RedundancyGrp != event.GroupID {
			continue
		}
		rc.activateReth(m)
	}
}

// activateReth brings up the RETH bond and its members,
// making this node the active forwarder for this RG.
func (rc *RethController) activateReth(m RethMapping) {
	if rc.nlHandle == nil {
		return
	}
	bond, err := rc.nlHandle.LinkByName(m.RethName)
	if err != nil {
		slog.Warn("reth activate: bond not found", "name", m.RethName, "err", err)
		return
	}

	// Bring up bond and all members.
	if err := rc.nlHandle.LinkSetUp(bond); err != nil {
		slog.Warn("reth activate: failed to bring up bond", "name", m.RethName, "err", err)
	}

	for _, member := range m.Members {
		link, err := rc.nlHandle.LinkByName(member)
		if err != nil {
			continue
		}
		rc.nlHandle.LinkSetUp(link)
	}

	slog.Info("reth bond UP", "name", m.RethName, "rg", m.RedundancyGrp)
}

// deactivateReth brings down the RETH bond members on this node,
// causing the active-backup bond to fail over to the peer.
func (rc *RethController) deactivateReth(m RethMapping) {
	if rc.nlHandle == nil {
		return
	}
	// In active-backup mode, bringing down the local member interfaces
	// causes the bond to switch to the peer's member (if available).
	for _, member := range m.Members {
		link, err := rc.nlHandle.LinkByName(member)
		if err != nil {
			continue
		}
		if err := rc.nlHandle.LinkSetDown(link); err != nil {
			slog.Warn("reth deactivate: failed to bring down member",
				"reth", m.RethName, "member", member, "err", err)
		}
	}

	slog.Info("reth deactivated (secondary)", "name", m.RethName, "rg", m.RedundancyGrp)
}

// RethIPs returns the IP addresses configured on a RETH interface.
// Returns both IPv4 and IPv6 addresses. Used for gratuitous ARP/NA after failover.
func (rc *RethController) RethIPs(rethName string) ([]net.IP, error) {
	link, err := rc.nlHandle.LinkByName(rethName)
	if err != nil {
		return nil, fmt.Errorf("reth %s not found: %w", rethName, err)
	}

	addrs, err := rc.nlHandle.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("reth %s addrs: %w", rethName, err)
	}

	var ips []net.IP
	for _, addr := range addrs {
		// Skip link-local IPv6 (fe80::) — not useful for GARP/NA.
		if addr.IP.To4() == nil && addr.IP.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

// FormatStatus returns RETH interface status for display.
func (rc *RethController) FormatStatus() string {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if len(rc.mappings) == 0 {
		return "No RETH interfaces configured\n"
	}

	var result string
	result += fmt.Sprintf("%-12s %-8s %-10s %s\n", "Interface", "RG", "Status", "Members")
	for _, m := range rc.mappings {
		status := "unknown"
		if rc.nlHandle != nil {
			link, err := rc.nlHandle.LinkByName(m.RethName)
			if err == nil {
				if link.Attrs().OperState == netlink.OperUp ||
					link.Attrs().Flags&net.FlagUp != 0 {
					status = "up"
				} else {
					status = "down"
				}
			} else {
				status = "missing"
			}
		}
		members := ""
		for i, mem := range m.Members {
			if i > 0 {
				members += ", "
			}
			members += mem
		}
		result += fmt.Sprintf("%-12s %-8d %-10s %s\n", m.RethName, m.RedundancyGrp, status, members)
	}
	return result
}
