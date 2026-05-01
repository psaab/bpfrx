// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"net"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// buildRAConfigs merges static RA configs from the Junos config with
// PD-derived prefixes from DHCPv6 prefix delegation.
func (d *Daemon) buildRAConfigs(cfg *config.Config) []*config.RAInterfaceConfig {
	// Start with static RA configs from the configuration.
	raByIface := make(map[string]*config.RAInterfaceConfig)
	var result []*config.RAInterfaceConfig
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		clone := cloneRAInterfaceConfig(ra)
		raByIface[clone.Interface] = clone
		result = append(result, clone)
	}

	if d.dhcp != nil {
		// Merge PD-derived prefixes from DHCPv6 clients.
		for _, mapping := range d.dhcp.DelegatedPrefixesForRA() {
			subPrefix := dhcp.DeriveSubPrefix(mapping.Prefix, mapping.SubPrefLen)
			if !subPrefix.IsValid() {
				slog.Warn("DHCPv6 PD: invalid sub-prefix derivation",
					"delegated", mapping.Prefix, "sub_len", mapping.SubPrefLen)
				continue
			}

			pfx := &config.RAPrefix{
				Prefix:     subPrefix.String(),
				OnLink:     true,
				Autonomous: true,
			}
			if mapping.ValidLifetime > 0 {
				pfx.ValidLifetime = int(mapping.ValidLifetime.Seconds())
			}
			if mapping.PreferredLifetime > 0 {
				pfx.PreferredLife = int(mapping.PreferredLifetime.Seconds())
			}

			if existing, ok := raByIface[mapping.RAIface]; ok {
				// Append prefix to existing RA interface config.
				existing.Prefixes = append(existing.Prefixes, pfx)
			} else {
				// Create a new RA interface config for this downstream interface.
				ra := &config.RAInterfaceConfig{
					Interface: mapping.RAIface,
					Prefixes:  []*config.RAPrefix{pfx},
				}
				raByIface[mapping.RAIface] = ra
				result = append(result, ra)
			}

			slog.Info("DHCPv6 PD: advertising prefix via RA",
				"prefix", subPrefix, "interface", mapping.RAIface,
				"delegated_from", mapping.Interface)
		}
	}

	// Detect explicitly configured link-local addresses on RA interfaces.
	// If a user configures e.g. fe80::face/64 on a RETH interface, the RA
	// sender should bind to that address instead of auto-selecting one.
	for _, ra := range result {
		if ifc, ok := cfg.Interfaces.Interfaces[ra.Interface]; ok {
			if unit, ok := ifc.Units[0]; ok {
				for _, addr := range unit.Addresses {
					ip, _, err := net.ParseCIDR(addr)
					if err != nil {
						continue
					}
					if ip.IsLinkLocalUnicast() && ip.To4() == nil {
						ra.SourceLinkLocal = ip.String()
						break
					}
				}
			}
			if ra.SourceLinkLocal == "" && cfg.Chassis.Cluster != nil && ifc.RedundancyGroup != 0 {
				// RETH HA startup installs a stable router link-local on the active
				// member. Bind RA to that address so the sender does not auto-pick a
				// transient EUI-64 link-local which can later be removed by HA reconcile.
				ra.SourceLinkLocal = cluster.StableRethLinkLocal(
					cfg.Chassis.Cluster.ClusterID,
					ifc.RedundancyGroup,
				).String()
			}
		}
	}

	// Resolve RETH interface names for RA senders (needs real Linux names).
	for _, ra := range result {
		ra.Interface = config.LinuxIfName(cfg.ResolveReth(ra.Interface))
	}

	return result
}

func cloneRAInterfaceConfig(src *config.RAInterfaceConfig) *config.RAInterfaceConfig {
	if src == nil {
		return nil
	}
	clone := *src
	if len(src.DNSServers) > 0 {
		clone.DNSServers = append([]string(nil), src.DNSServers...)
	}
	if len(src.Prefixes) > 0 {
		clone.Prefixes = make([]*config.RAPrefix, 0, len(src.Prefixes))
		for _, pfx := range src.Prefixes {
			if pfx == nil {
				clone.Prefixes = append(clone.Prefixes, nil)
				continue
			}
			pfxClone := *pfx
			clone.Prefixes = append(clone.Prefixes, &pfxClone)
		}
	}
	return &clone
}
