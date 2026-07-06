package config

import (
	"net"
	"sort"
	"strings"
)

// Shared RETH resolution for the `show interfaces` text surfaces (#4328).
//
// A bondless reth (VRRP on the physical member interfaces, no kernel bond
// device) has NO kernel netdev of its own — nothing is named "reth0". Only the
// `terse` handler resolved this, by building the physical<->reth maps from
// cfg.RethToPhysical(); every other operational path (`show interfaces reth0`,
// `... detail`, `... extensive`) did a raw kernel-netdev lookup that could not
// succeed for a reth and rendered "Not present" / empty / "not found". This
// file folds the map-building out of the terse handler so terse, summary,
// detail, and extensive all classify a reth identically and can never drift
// again.

// RethShowMaps bundles the two reth lookup directions the `show interfaces`
// text surfaces need.
type RethShowMaps struct {
	// PhysToReth maps a physical redundant-ether member to its reth parent.
	// Keyed by BOTH the Junos config name ("ge-0/0/2") and the Linux/kernel
	// name ("ge-0-0-2") so a caller that starts from a kernel ifname (the
	// detail / extensive netlink.LinkList walk) resolves as readily as one
	// that starts from a config name (the terse / summary walk).
	PhysToReth map[string]string
	// RethToPhys maps a reth aggregate to its LOCAL physical member, in Junos
	// name form (as RethToPhysical returns). reth names carry no slash, so no
	// dual-keying is required.
	RethToPhys map[string]string
}

// RethShowMaps builds the reth lookup maps for a `show interfaces` surface.
// The returned maps are freshly allocated, so a caller may add peer-node
// members to PhysToReth (the terse cluster path does this) without mutating
// shared state.
func (c *Config) RethShowMaps() RethShowMaps {
	physToReth := make(map[string]string)
	for _, ifc := range c.Interfaces.Interfaces {
		if ifc == nil || ifc.RedundantParent == "" {
			continue
		}
		physToReth[ifc.Name] = ifc.RedundantParent
		if ln := LinuxIfName(ifc.Name); ln != ifc.Name {
			physToReth[ln] = ifc.RedundantParent
		}
	}
	return RethShowMaps{PhysToReth: physToReth, RethToPhys: c.RethToPhysical()}
}

// rethShowBase strips a dotted unit suffix ("reth0.50" -> "reth0").
func rethShowBase(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// LookupReth reports whether name (or its base before ".") is a reth aggregate
// and, if so, returns the reth parent name and its local physical member
// (Junos name form — LinuxIfName it before a kernel lookup).
func (m RethShowMaps) LookupReth(name string) (reth, physMember string, ok bool) {
	base := rethShowBase(name)
	if phys, found := m.RethToPhys[base]; found {
		return base, phys, true
	}
	return "", "", false
}

// LookupMember reports whether name (or its base, in Junos or kernel form) is a
// physical reth member and, if so, returns its reth parent name.
func (m RethShowMaps) LookupMember(name string) (reth string, ok bool) {
	base := rethShowBase(name)
	reth, ok = m.PhysToReth[base]
	return reth, ok
}

// RethShowUnit is one logical unit of a reth aggregate resolved for display:
// its unit number, VLAN tag, and configured addresses split by family. The
// addresses come from config because the reth has no kernel netdev — the
// kernel addresses live on the physical member's VLAN sub-interfaces.
type RethShowUnit struct {
	Unit    int
	VlanID  int
	V4Addrs []string
	V6Addrs []string
}

// RethShowUnits returns reth's logical units sorted by unit number, with the
// configured addresses split into v4/v6, for a `show interfaces` surface.
// Returns nil when reth is not a configured aggregate. Shared so every surface
// orders units and splits addresses identically.
func (c *Config) RethShowUnits(reth string) []RethShowUnit {
	ifc, ok := c.Interfaces.Interfaces[reth]
	if !ok || ifc == nil {
		return nil
	}
	out := make([]RethShowUnit, 0, len(ifc.Units))
	for num, unit := range ifc.Units {
		if unit == nil {
			continue
		}
		ru := RethShowUnit{Unit: num, VlanID: unit.VlanID}
		for _, addr := range unit.Addresses {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				ru.V4Addrs = append(ru.V4Addrs, addr)
			} else {
				ru.V6Addrs = append(ru.V6Addrs, addr)
			}
		}
		out = append(out, ru)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Unit < out[j].Unit })
	return out
}
