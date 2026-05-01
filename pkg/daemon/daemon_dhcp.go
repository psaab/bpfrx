// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"slices"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// startDHCPClients iterates the config and starts DHCP/DHCPv6 clients
// for interfaces that have family inet { dhcp; } or family inet6 { dhcpv6; }.
func (d *Daemon) startDHCPClients(ctx context.Context, cfg *config.Config) {
	// Check if any interface needs DHCP
	needsDHCP := false
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			if unit.DHCP || unit.DHCPv6 {
				needsDHCP = true
				break
			}
		}
	}
	if !needsDHCP {
		return
	}

	// State dir for DUID persistence — same directory as config file
	stateDir := filepath.Dir(d.opts.ConfigFile)

	dm, err := dhcp.New(stateDir, func() {
		// Full recompile is safe: heartbeat sockets survive VRF rebind
		// (RestartHeartbeat), RETH MAC is set live (no XSK rebind), and
		// BPF compile skips reconcile when the binding plan is unchanged.
		if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
			if d.dhcpLeaseChangeRequiresRecompile(activeCfg) {
				slog.Info("DHCP address changed, recompiling dataplane")
				d.applyConfig(activeCfg)
			} else {
				slog.Info("DHCP address changed on management-only interface, refreshing management routes")
				d.applyMgmtVRFRoutes()
			}
		}
	})
	if err != nil {
		slog.Warn("failed to create DHCP manager", "err", err)
		return
	}
	d.dhcp = dm

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			// Use VLAN sub-interface name when unit has a VLAN ID
			dhcpIface := config.LinuxIfName(ifName)
			if unit.VlanID > 0 {
				dhcpIface = fmt.Sprintf("%s.%d", dhcpIface, unit.VlanID)
			}
			if unit.DHCP {
				if unit.DHCPOptions != nil {
					dm.SetDHCPv4Options(dhcpIface, &dhcp.DHCPv4Options{
						LeaseTime:              unit.DHCPOptions.LeaseTime,
						RetransmissionAttempt:  unit.DHCPOptions.RetransmissionAttempt,
						RetransmissionInterval: unit.DHCPOptions.RetransmissionInterval,
						ForceDiscover:          unit.DHCPOptions.ForceDiscover,
					})
				}
				slog.Info("starting DHCPv4 client", "interface", dhcpIface)
				dm.Start(ctx, dhcpIface, dhcp.AFInet)
			}
			if unit.DHCPv6 {
				// Configure DUID type from dhcpv6-client stanza
				if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
					dm.SetDUIDType(dhcpIface, unit.DHCPv6Client.DUIDType)
				} else {
					dm.SetDUIDType(dhcpIface, "duid-ll") // default
				}
				// Configure DHCPv6 PD and other options
				if unit.DHCPv6Client != nil {
					dm.SetDHCPv6Options(dhcpIface, &dhcp.DHCPv6Options{
						Stateless:  unit.DHCPv6Client.ClientType == "stateless",
						UpdateDNS:  slices.Contains(unit.DHCPv6Client.ReqOptions, "dns-server"),
						IATypes:    unit.DHCPv6Client.ClientIATypes,
						PDPrefLen:  unit.DHCPv6Client.PrefixDelegatingPrefixLen,
						PDSubLen:   unit.DHCPv6Client.PrefixDelegatingSubPrefLen,
						ReqOptions: unit.DHCPv6Client.ReqOptions,
						RAIface:    unit.DHCPv6Client.UpdateRAInterface,
					})
				}
				slog.Info("starting DHCPv6 client", "interface", dhcpIface)
				dm.Start(ctx, dhcpIface, dhcp.AFInet6)
			}
		}
	}
}

func (d *Daemon) dhcpLeaseChangeRequiresRecompile(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	// Prefix delegation can affect downstream addressing/RA and still needs
	// a full re-apply.
	if d.dhcp != nil && len(d.dhcp.DelegatedPrefixesForRA()) > 0 {
		return true
	}
	// If management VRF bindings are unavailable, stay conservative.
	if len(d.mgmtVRFInterfaces) == 0 {
		return true
	}
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
				continue
			}
			dhcpIface := config.LinuxIfName(ifName)
			if unit.VlanID > 0 {
				dhcpIface = fmt.Sprintf("%s.%d", dhcpIface, unit.VlanID)
			}
			if !d.mgmtVRFInterfaces[dhcpIface] {
				return true
			}
		}
	}
	return false
}

// resolveJunosIfName converts a Junos-style interface name to its Linux
// equivalent. It resolves RETH names to their physical members (e.g.
// reth0.50 → ge-0/0/0.50) and converts Junos slashes to dashes (e.g.
// ge-0/0/0 → ge-0-0-0).
func resolveJunosIfName(cfg *config.Config, ifName string) string {
	return config.LinuxIfName(cfg.ResolveReth(ifName))
}

func resolveConfigSubnetLinuxName(cfg *config.Config, ip net.IP) (string, string, bool) {
	if cfg == nil || ip == nil {
		return "", "", false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, addrStr := range unit.Addresses {
				_, ipNet, err := net.ParseCIDR(addrStr)
				if err != nil {
					continue
				}
				if !ipNet.Contains(ip) {
					continue
				}
				ifName := resolveJunosIfName(cfg, ifc.Name)
				if unit.VlanID > 0 {
					ifName = fmt.Sprintf("%s.%d", ifName, unit.VlanID)
				} else if unitNum != 0 {
					ifName = fmt.Sprintf("%s.%d", ifName, unitNum)
				}
				return ifName, addrStr, true
			}
		}
	}
	return "", "", false
}

// stripCIDR removes the /prefix from a CIDR string, returning just the IP.
func stripCIDR(s string) string {
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		return s // not CIDR, return as-is
	}
	return ip.String()
}
