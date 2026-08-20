package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// The host-inbound LIFELINE matcher is the SSOT in pkg/config (lifeline.go,
// #3682) so the shared host-inbound presenter can render the exemption on the
// operator-visible zone views. These thin wrappers keep the dataplane call sites
// and the #3277 fail-on-revert tests reading against the local names while the
// matching logic (fxp0 + configured control/fabric + em0/fab* defaults) lives in
// exactly one place shared with display.

func hostInboundLifelineSet(cfg *config.Config) map[string]bool {
	return config.HostInboundLifelineSet(cfg)
}

func hostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	return config.HostInboundLifelineInterface(name, lifelines)
}

// hostIPFromCIDR returns the bare host IP of a "ip/prefix" string (or a bare
// IP). Returns "" if unparseable.
func hostIPFromCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil && ip != nil {
		return ip.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// authoredZoneRefs returns the operator's LITERAL `security-zone <z> interfaces
// <ref>` bindings — canonicalised through CanonicalInterfaceUnitRef so ".01" and
// ".1" agree with the snapshot's unit naming, but NOT fanned up to a base and
// NOT fanned down onto units (#6722).
//
// It is the PROVENANCE half of buildInterfaceZoneMap. That map deliberately
// derives: a unit-suffixed reference also writes `out[base]`, and a bare
// reference also writes `out[base.<unit>]` for every configured unit. Those
// derived entries are right for the INGRESS attribution they were built for, but
// they are restatements of one operator sentence, not independent statements —
// and once several config identities collapse onto ONE netdev
// (`snapshotLinuxName`), a derived entry becomes indistinguishable from an
// authored one by inspection of the result alone. stampEgressZones (the sole
// consumer of this map, in interfaces.go) needs to tell them apart, so the
// provenance is recorded here rather than
// reconstructed downstream from the outcome. Reconstructing it is exactly what
// #6722 attempted four times, and each attempt was holed by a new config shape.
//
// The write policy mirrors buildInterfaceZoneMap exactly — sorted zone names,
// first-write-wins — so a reference claimed by two zones resolves to the SAME
// zone in both maps and this function introduces no second opinion about it.
func authoredZoneRefs(cfg *config.Config) map[string]string {
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
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			iface := config.CanonicalInterfaceUnitRef(rawIface)
			if _, exists := out[iface]; !exists {
				out[iface] = zoneName
			}
		}
	}
	return out
}

// quarantinedZoneNames returns the zone names the StableZoneID quarantine will
// drop for this config (#6722). It reads the SAME name set quarantineCollidingZones
// does — buildZoneSnapshots publishes exactly cfg.Security.Zones — so the two
// cannot drift apart.
func quarantinedZoneNames(cfg *config.Config) map[string]struct{} {
	if cfg == nil || len(cfg.Security.Zones) < 2 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	return config.QuarantinedZoneNames(names)
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
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			// #5878 phase 2: bind the zone reference on its CANONICAL logical-unit
			// identity so ge-0/0/0.01 and ge-0/0/0.1 resolve to the same runtime
			// unit as the interface's `unit 1` definition. The per-unit snapshot
			// consumer (buildInterfaceSnapshots) keys this map by the canonical
			// "%s.%d" unit name, so a raw ".01" key would miss and the unit would
			// bind to NO zone. A bare ref or a malformed suffix is unchanged.
			iface := config.CanonicalInterfaceUnitRef(rawIface)
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
