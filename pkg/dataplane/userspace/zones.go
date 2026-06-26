package userspace

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func buildZoneSnapshots(cfg *config.Config) []ZoneSnapshot {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ZoneSnapshot, 0, len(names))
	for i, name := range names {
		z := ZoneSnapshot{
			Name: name,
			ID:   uint16(i + 1),
		}
		// #3070: carry the zone's host-inbound-traffic admission set onto the
		// wire so the dataplane can enforce it for host-bound (local-delivery)
		// traffic. A nil HostInboundTraffic means the zone declared no stanza:
		// HostInboundConfigured stays false and the dataplane preserves
		// admit-all for that zone.
		if zone := cfg.Security.Zones[name]; zone != nil && zone.HostInboundTraffic != nil {
			z.HostInboundConfigured = true
			z.HostInboundSystemServices = lowerTokens(zone.HostInboundTraffic.SystemServices)
			z.HostInboundProtocols = lowerTokens(zone.HostInboundTraffic.Protocols)
		}
		out = append(out, z)
	}
	return out
}

// lowerTokens returns a lower-cased, trimmed copy of the host-inbound token
// slice (system-services / protocols). Empty/whitespace tokens are dropped.
// The Rust classifier lower-cases on its side too, but normalizing here keeps
// the wire canonical and the Go emit test deterministic.
func lowerTokens(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildInterfaceZoneMap(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg.Security.Zones))
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == "" {
				continue
			}
			if _, exists := out[iface]; !exists {
				out[iface] = zoneName
			}
			if base, unit, ok := strings.Cut(iface, "."); ok && base != "" {
				if _, exists := out[base]; !exists {
					out[base] = zoneName
				}
				if unit != "" {
					continue
				}
			}
			if ifCfg := cfg.Interfaces.Interfaces[iface]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					unitName := fmt.Sprintf("%s.%d", iface, unitNum)
					if _, exists := out[unitName]; !exists {
						out[unitName] = zoneName
					}
				}
			}
		}
	}
	return out
}
