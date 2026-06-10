// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// buildDHCPClientSpecs computes the desired DHCP client set from the
// config: one spec per unit with family inet { dhcp; } or family inet6
// { dhcpv6; }. Specs carry config identity only (interface, family,
// client options) — never lease or address state — so the reconcile
// diff is stable across lease changes (#1793, plan §5.4).
func buildDHCPClientSpecs(cfg *config.Config) []dhcp.ClientSpec {
	var specs []dhcp.ClientSpec
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
				continue
			}
			// Shared lease-key derivation (#1844): the same helper the
			// ip-monitoring compiler uses for interface-typed next-hops,
			// so the two derivations can never drift.
			dhcpIface := config.DHCPLeaseIfName(ifName, unit)
			if unit.DHCP {
				spec := dhcp.ClientSpec{Iface: dhcpIface, Family: dhcp.AFInet}
				if unit.DHCPOptions != nil {
					spec.V4 = &dhcp.DHCPv4Options{
						LeaseTime:              unit.DHCPOptions.LeaseTime,
						RetransmissionAttempt:  unit.DHCPOptions.RetransmissionAttempt,
						RetransmissionInterval: unit.DHCPOptions.RetransmissionInterval,
						ForceDiscover:          unit.DHCPOptions.ForceDiscover,
					}
				}
				specs = append(specs, spec)
			}
			if unit.DHCPv6 {
				spec := dhcp.ClientSpec{
					Iface:    dhcpIface,
					Family:   dhcp.AFInet6,
					DUIDType: "duid-ll", // default
				}
				if unit.DHCPv6Client != nil {
					if unit.DHCPv6Client.DUIDType != "" {
						spec.DUIDType = unit.DHCPv6Client.DUIDType
					}
					spec.V6 = &dhcp.DHCPv6Options{
						Stateless:  unit.DHCPv6Client.ClientType == "stateless",
						IATypes:    unit.DHCPv6Client.ClientIATypes,
						PDPrefLen:  unit.DHCPv6Client.PrefixDelegatingPrefixLen,
						PDSubLen:   unit.DHCPv6Client.PrefixDelegatingSubPrefLen,
						ReqOptions: unit.DHCPv6Client.ReqOptions,
						RAIface:    unit.DHCPv6Client.UpdateRAInterface,
					}
				}
				specs = append(specs, spec)
			}
		}
	}
	return specs
}

// onDHCPAddressChange is the (debounced) lease-change callback for the
// DHCP manager. It re-enters applyConfig, which is why the client
// reconcile must key on config identity only — see reconcileDHCPClients.
func (d *Daemon) onDHCPAddressChange() {
	// Full recompile is safe: heartbeat sockets survive VRF rebind
	// (RestartHeartbeat), RETH MAC is set live (no XSK rebind), and
	// BPF compile skips reconcile when the binding plan is unchanged.
	if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
		if d.dhcpLeaseChangeRequiresRecompile(activeCfg) {
			slog.Info("DHCP address changed, recompiling dataplane")
			// applyConfig runs reconcileDNSLocked, so DNS is
			// reconciled with the new lease set on this path.
			d.applyConfig(activeCfg)
		} else {
			slog.Info("DHCP address changed on management-only interface, refreshing management routes")
			d.applyMgmtVRFRoutes()
			// #1715 (fw0 class): a management-only interface (e.g.
			// fxp0 DHCPv4) takes this branch and does NOT recompile,
			// so DNS would never reconcile without this call. Route
			// the DHCP-learned DNS through the locked reconciler so
			// the box always picks up DHCP nameservers, not just on
			// dataplane-relevant interfaces.
			d.reconcileDNSFromDHCP()
		}
	}
}

// reconcileDHCPClients converges running DHCP/DHCPv6 clients with the
// given config (#1793): newly enabled units get a client, units whose
// dhcp/dhcpv6 stanza was deleted get their client stopped (stop renewing
// + remove the leased address; no protocol RELEASE), and option changes
// restart the affected client. Called from applyConfigLocked on every
// apply, so commit-time enable/disable behaves like Junos instead of
// boot-time-only. The DHCP manager is created eagerly in Run (#1844,
// AGY plan r2-1) — d.dhcp is write-once at boot, so there is no
// lazy-create branch here and no pointer race against the bare reads
// in the ipmon resolver and the CLI/gRPC handlers.
func (d *Daemon) reconcileDHCPClients(cfg *config.Config) {
	if d.opts.NoDataplane || d.dhcp == nil {
		return
	}
	specs := buildDHCPClientSpecs(cfg)
	if len(specs) == 0 {
		// Reconcile(nil) stops any running clients; with none running
		// it is a no-op.
		d.dhcp.Reconcile(nil)
		return
	}
	d.dhcp.Reconcile(specs)
}

// resolveDHCPNextHop is the ipmon NextHopResolver (#1844): it maps an
// interface-typed preferred-route lease key
// (PreferredRoute.NextHopInterface, derived via config.DHCPLeaseIfName)
// to the unit's current DHCPv4-learned gateway. ok=false — no DHCP
// manager (NoDataplane), no lease yet, or a lease without a router
// option — makes the engine skip the candidate BEFORE winner
// selection. Called under Engine.mu; LeaseFor takes dhcp.Manager.mu
// briefly (the one-way Engine.mu → dhcp.mu lock order) and never calls
// back into the engine.
func (d *Daemon) resolveDHCPNextHop(leaseIface string) (string, bool) {
	dm := d.dhcp // write-once at boot (Run), safe to read bare
	if dm == nil {
		return "", false
	}
	lease := dm.LeaseFor(leaseIface, dhcp.AFInet)
	if lease == nil || !lease.Gateway.IsValid() || lease.Gateway.IsUnspecified() {
		return "", false
	}
	return lease.Gateway.String(), true
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
			if !d.mgmtVRFInterfaces[config.DHCPLeaseIfName(ifName, unit)] {
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
//
// NOTE: Keep in sync with (*Config).ResolveKernelIfName in
// pkg/config/types.go. This helper only does the bare-ref subset of
// the public method; callers that already have unit/vlan context
// build the .VLAN suffix themselves (see resolveConfigSubnetLinuxName).
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
