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
// Physical member interfaces are kept UP on both nodes so VRRP can
// send advertisements. No bond devices — VRRP runs directly on physical.
func (rc *RethController) HandleStateChange(event ClusterEvent) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, m := range rc.mappings {
		if m.RedundancyGrp != event.GroupID {
			continue
		}
		if rc.nlHandle == nil {
			continue
		}
		// Bring up physical member interfaces (VRRP needs them UP on both nodes)
		for _, member := range m.Members {
			link, err := rc.nlHandle.LinkByName(member)
			if err != nil {
				continue
			}
			rc.nlHandle.LinkSetUp(link)
		}
		slog.Info("reth physical members UP", "reth", m.RethName, "rg", m.RedundancyGrp)
	}
}

// RethIPs returns the IP addresses on a RETH's physical member interface.
func (rc *RethController) RethIPs(rethName string) ([]net.IP, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	for _, m := range rc.mappings {
		if m.RethName == rethName && len(m.Members) > 0 {
			link, err := rc.nlHandle.LinkByName(m.Members[0])
			if err != nil {
				return nil, fmt.Errorf("physical member %s for reth %s not found: %w", m.Members[0], rethName, err)
			}
			addrs, err := rc.nlHandle.AddrList(link, netlink.FAMILY_ALL)
			if err != nil {
				return nil, fmt.Errorf("addrs on %s: %w", m.Members[0], err)
			}
			var ips []net.IP
			for _, addr := range addrs {
				if addr.IP.To4() == nil && addr.IP.IsLinkLocalUnicast() {
					continue
				}
				ips = append(ips, addr.IP)
			}
			return ips, nil
		}
	}
	return nil, fmt.Errorf("reth %s not found", rethName)
}

// FormatStatus returns RETH interface status for display.
func (rc *RethController) FormatStatus() string {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if len(rc.mappings) == 0 {
		return "No RETH interfaces configured\n"
	}

	var result string
	result += fmt.Sprintf("%-12s %-8s %-10s %s\n", "Interface", "RG", "Status", "Physical")
	for _, m := range rc.mappings {
		status := "unknown"
		if rc.nlHandle != nil && len(m.Members) > 0 {
			link, err := rc.nlHandle.LinkByName(m.Members[0])
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
