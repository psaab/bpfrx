// Daemon-side glue invoked from CLI commit / rollback paths. The CLI
// owns these only when no daemon-supplied apply callback has been
// wired; in production xpfd wires applyConfigFn to its own reconcile
// loop and these helpers are skipped.
package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/logging"
)

// reloadSyslog rebuilds the syslog client set and zone-name mapping from
// the supplied config. Safe to call with a nil event reader.
func (c *CLI) reloadSyslog(cfg *config.Config) {
	if c.eventReader == nil {
		return
	}
	// Update zone name mapping for structured log format
	// Uses sorted zone names → sequential IDs (matches compiler order)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	znMap := make(map[uint16]string, len(names))
	for i, name := range names {
		znMap[uint16(i+1)] = name
	}
	c.eventReader.SetZoneNames(znMap)

	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		client, err := logging.NewSyslogClient(stream.Host, stream.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: syslog stream %s: %v\n", name, err)
			continue
		}
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
		}
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
		}
		clients = append(clients, client)
	}
	c.eventReader.ReplaceSyslogClients(clients)
}

// applyToDataplane drives the legacy CLI-side apply sequence: tunnel
// interfaces, eBPF compile, FRR config, then IPsec. Only used when the
// daemon does not wire applyConfigFn (e.g. CLI spawned standalone for
// testing). When applyConfigFn IS wired, the daemon's full reconcile
// runs instead and this function is skipped.
func (c *CLI) applyToDataplane(cfg *config.Config) error {
	// 1. Create tunnel interfaces first
	if c.routing != nil {
		var tunnels []*config.TunnelConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
				tunnels = append(tunnels, ifc.Tunnel)
			}
			for _, unit := range ifc.Units {
				if unit.Tunnel != nil {
					tunnels = append(tunnels, unit.Tunnel)
				}
			}
		}
		if err := c.routing.ApplyTunnels(tunnels); err != nil {
			fmt.Fprintf(os.Stderr, "warning: tunnel apply failed: %v\n", err)
		}
		if err := c.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: xfrmi apply failed: %v\n", err)
		}
	}

	// 2. Compile eBPF dataplane
	if c.dp != nil && c.dp.IsLoaded() {
		if _, err := c.dp.Compile(cfg); err != nil {
			return err
		}
	}

	// 3. Apply all routes + dynamic protocols via FRR
	if c.frr != nil {
		// Collect interface bandwidths and point-to-point flags for FRR.
		ifaceBandwidths := make(map[string]uint64)
		ifaceP2P := make(map[string]bool)
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc.Bandwidth > 0 {
				ifaceBandwidths[name] = ifc.Bandwidth
			}
			for _, unit := range ifc.Units {
				if unit.PointToPoint {
					ifaceP2P[name] = true
				}
			}
		}

		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			OSPFv3:                cfg.Protocols.OSPFv3,
			BGP:                   cfg.Protocols.BGP,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			InterfaceBandwidths:   ifaceBandwidths,
			InterfacePointToPoint: ifaceP2P,
		}
		if c.dhcp != nil {
			for _, lease := range c.dhcp.Leases() {
				if !lease.Gateway.IsValid() {
					continue
				}
				fc.DHCPRoutes = append(fc.DHCPRoutes, frr.DHCPRoute{
					Gateway:   lease.Gateway.String(),
					Interface: lease.Interface,
					IsIPv6:    lease.Family == dhcp.AFInet6,
				})
			}
		}
		for _, ri := range cfg.RoutingInstances {
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:      "vrf-" + ri.Name,
				OSPF:         ri.OSPF,
				OSPFv3:       ri.OSPFv3,
				BGP:          ri.BGP,
				StaticRoutes: ri.StaticRoutes,
			})
		}
		if err := c.frr.ApplyFull(fc); err != nil {
			fmt.Fprintf(os.Stderr, "warning: FRR apply failed: %v\n", err)
		}
	}

	// 5. Apply IPsec config
	if c.ipsec != nil {
		if err := c.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: IPsec apply failed: %v\n", err)
		}
	}

	return nil
}
