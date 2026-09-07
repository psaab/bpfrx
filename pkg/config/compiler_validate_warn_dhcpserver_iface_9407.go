package config

import (
	"fmt"
	"sort"
)

// validateDHCPServerInterfaceRefWarnings closes the residual #9407 leaves.
//
// `system services dhcp-local-server group <g> interface <ref>` (and the
// DHCPv6 twin) names the segment Kea serves. The daemon resolves it to a kernel
// device through Config.ResolveKernelIfName (#9407), and that resolver has an
// honest limit: when the ref names a unit the config never declares, it cannot
// know what device was meant and returns the ref verbatim — `reth1.0` stays
// `ge-0-0-1.0`, which is not a device.
//
// That residual is not worth GUESSING at (a blanket ".0" strip would also
// rewrite a legitimately dotted DECLARED interface name, the #8994 case). It is
// worth SAYING. A group whose unit is undeclared has no address either, so Kea
// could not have matched a subnet on it even with a perfect device name — the
// config is broken, and the operator should hear that at commit rather than
// discover it as a segment that never gets leases.
//
// Advisory rather than gate, per #1960, and for the same reason as the sibling
// #9405 / #9406 advisories: the tolerant load and HA config-sync paths must
// still accept a config whose interface set does not explain every reference.
//
// Families and groups are walked in sorted order so the message set is
// deterministic.
func validateDHCPServerInterfaceRefWarnings(cfg *Config) []string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	families := []struct {
		label string
		local *DHCPLocalServerConfig
	}{
		{"dhcp-local-server", cfg.System.DHCPServer.DHCPLocalServer},
		{"dhcpv6-local-server", cfg.System.DHCPServer.DHCPv6LocalServer},
	}

	var declared map[string]*InterfaceConfig
	var warnings []string
	for _, fam := range families {
		if fam.local == nil || len(fam.local.Groups) == 0 {
			continue
		}
		if declared == nil {
			declared = declaredInterfaceIndex(cfg)
		}
		names := make([]string, 0, len(fam.local.Groups))
		for name := range fam.local.Groups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			g := fam.local.Groups[name]
			if g == nil {
				continue
			}
			for _, ref := range g.Interfaces {
				if ref == "" {
					continue
				}
				reason := unresolvedInterfaceRef(declared, ref)
				if reason == "" {
					continue
				}
				warnings = append(warnings, fmt.Sprintf(
					"system services %s group %s interface %s %s — Kea will be "+
						"given a device name the kernel does not have, and the "+
						"segment gets no leases (#9407).",
					fam.label, name, ref, reason))
			}
		}
	}
	return warnings
}
