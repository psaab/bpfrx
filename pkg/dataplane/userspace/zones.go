package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ZoneHostInboundView is the per-zone host-inbound-traffic enforcement view for
// the KERNEL-nftables primary path (#3070). Ordinary host-bound traffic to a
// firewall interface IP / VRRP VIP (SSH, ping, OSPF/BGP to the box) is shunted
// to the Linux kernel by the XDP shim before it ever reaches userspace-dp, so
// the authoritative host-inbound enforcement for those packets must live in the
// kernel `chain input` (mirroring the lo0-filter precedent). The userspace-dp
// LocalDelivery check (forwarding/host_inbound.rs) remains the secondary path
// for the narrow subset that DOES reach the XSK (DNAT-to-self, static-NAT to a
// firewall service, embedded-ICMP, DNS edge cases).
//
// One view is produced per host-inbound-CONFIGURED zone, carrying the zone's
// allowed Junos tokens plus its resolved firewall-local host addresses (bare
// IPs, prefix stripped), split by family. The daemon maps the tokens to nft
// matches and emits accept-the-listed / deny-the-rest rules scoped to those
// addresses.
type ZoneHostInboundView struct {
	Zone           string
	SystemServices []string
	Protocols      []string
	V4Addrs        []string // bare host IPv4 addresses (no prefix)
	V6Addrs        []string // bare host IPv6 addresses (no prefix)
}

// lifelineBaseName strips the unit suffix (".0") and surrounding whitespace from
// a logical interface name, returning the bare device name used for lifeline
// matching ("fxp0.0" -> "fxp0", "fab1.0" -> "fab1"). Returns "" for an empty
// name.
func lifelineBaseName(name string) string {
	base := strings.TrimSpace(name)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base
}

// hostInboundLifelineSet resolves the set of management / cluster-control
// LIFELINE interface base names that must NEVER be subjected to a host-inbound
// deny. It is the config-aware superset of the always-on defaults:
//
//   - fxp0 (out-of-band management) is always a lifeline.
//   - The chassis-cluster control-interface and fabric interface(s) are added
//     from config so an operator-renamed control link (e.g.
//     `control-interface fxp1`) or a non-default fabric name is excluded too.
//     This is the #3277 fix: the old matcher hardcoded fxp0/em0/fab* and so left
//     a configured `control-interface fxp1` SUBJECT to host-inbound deny scoping
//     -> potential heartbeat drop -> HA split-brain.
//
// em0 (the canonical cluster-control default name) and the fabric prefix fab*
// stay matched unconditionally in hostInboundLifelineInterface so the canonical
// default-named configs remain byte-identical (#3070/#3172/#3224 behavior is
// preserved). A standalone config (no chassis-cluster stanza) contributes no
// extra names here, so its only lifeline is fxp0 (em0/fab* are no-ops because
// such interfaces are not present) — #1960.
func hostInboundLifelineSet(cfg *config.Config) map[string]bool {
	set := map[string]bool{"fxp0": true}
	if cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			if base := lifelineBaseName(name); base != "" {
				set[base] = true
			}
		}
	}
	return set
}

// hostInboundLifelineInterface reports whether the given logical interface name
// is a management / cluster-control LIFELINE that must NEVER be subjected to a
// host-inbound deny. The lifeline set is the config-derived set (fxp0 plus the
// configured chassis-cluster control-interface / fabric interfaces, #3277) UNION
// the always-on backward-compatible defaults em0 (cluster control plane /
// heartbeat default name) and the fabric links (fab*). Denying host-bound
// traffic on these would strand management or break HA. The base name (before
// the unit suffix) is matched so "fxp0.0" / "em0.0" are caught too.
func hostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	base := lifelineBaseName(name)
	if base == "" {
		return false
	}
	if lifelines[base] {
		return true
	}
	return base == "em0" || strings.HasPrefix(base, "fab")
}

// BuildZoneHostInboundViews returns one ZoneHostInboundView per
// host-inbound-CONFIGURED zone (#3070), resolving each zone's firewall-local
// host addresses via the canonical interface-snapshot builder (the same
// resolution that populates the dataplane) PLUS each zone's RETH VRRP virtual
// addresses (#3172, resolved from config so they scope the deny on the backup
// node too, where the VIP is not yet live on the kernel interface), with
// management/cluster-control lifeline interfaces (fxp0 / em0 / fab*) excluded
// from the address set.
//
// Address completeness (#3224 — non-reproducing): the snapshot builder resolves
// each interface's addresses through buildLinkSnapshot -> AddrList(FAMILY_ALL),
// which enumerates EVERY kernel address with no scope/flag/dynamic filtering.
// So DHCP / DHCPv6-learned addresses are captured exactly like static ones —
// a DHCP-only interface with a live lease yields a NON-empty address set and IS
// scoped by the deny. (xpfd disables IPv6 RA on every managed interface in
// pkg/networkd, so DHCPv6 is the only IPv6 dynamic-address path and the same
// snapshot captures it; SLAAC is not a separate case.) The deny is also
// re-rendered on every DHCP/DHCPv6 lease change on a dataplane interface
// (onDHCPAddressChange -> dhcpLeaseChangeRequiresRecompile -> applyConfig ->
// applyHostInboundFilter), so a renewed/flapped lease re-scopes within one
// reconcile pass. #3224 was filed on the premise that DHCP addresses fell out
// of scope (FAIL OPEN); that does not reproduce because the live snapshot has
// always carried them — see TestBuildZoneHostInboundViewsScopesKernelLearnedAddr,
// which exercises this real path with a config-absent kernel address.
//
// A zone that declared NO host-inbound-traffic stanza is omitted entirely
// (admit-all preserved — zero regression). The only no-address case left is a
// configured zone whose interfaces have neither a static config address nor any
// live kernel address yet (e.g. a DHCP WAN before its first lease, or a backup
// node before VIP install): it yields an empty address set, the daemon emits no
// deny for it, and it self-heals once an address appears because the
// lease-change / commit paths re-render.
func BuildZoneHostInboundViews(cfg *config.Config) []ZoneHostInboundView {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	ifaceSnaps := buildInterfaceSnapshots(cfg)
	// Lifeline interfaces (fxp0 + the configured chassis-cluster
	// control-interface / fabric interfaces, plus the em0/fab* defaults) are
	// excluded from host-inbound deny scoping so management / cluster-control
	// traffic is never denied (#3277).
	lifelines := hostInboundLifelineSet(cfg)
	// Gather per-zone host addresses from the resolved interface snapshots,
	// skipping lifeline interfaces.
	type addrSet struct {
		v4    []string
		v6    []string
		seen4 map[string]bool
		seen6 map[string]bool
	}
	byZone := make(map[string]*addrSet)
	for _, snap := range ifaceSnaps {
		if snap.Zone == "" || hostInboundLifelineInterface(snap.Name, lifelines) {
			continue
		}
		set := byZone[snap.Zone]
		if set == nil {
			set = &addrSet{seen4: map[string]bool{}, seen6: map[string]bool{}}
			byZone[snap.Zone] = set
		}
		for _, a := range snap.Addresses {
			host := hostIPFromCIDR(a.Address)
			if host == "" {
				continue
			}
			if strings.Contains(host, ":") {
				if !set.seen6[host] {
					set.seen6[host] = true
					set.v6 = append(set.v6, host)
				}
			} else if !set.seen4[host] {
				set.seen4[host] = true
				set.v4 = append(set.v4, host)
			}
		}
	}

	// VRRP RETH VIPs (#3172): the host-inbound destination address set must
	// also include each zone's RETH virtual IPs, not only the static interface
	// addresses resolved above. A VIP is present on the kernel interface ONLY of
	// the node that currently owns the redundancy group (master); on the backup
	// node the VIP is absent from buildLinkSnapshot's live address list, so
	// without this the kernel host-inbound deny would not be scoped to the VIP
	// and `chain input` would fall through to `policy accept` (FAIL-OPEN) for
	// VIP-destined host-bound traffic. The VIPs are identical on both nodes, so
	// resolving them from config (unit.VRRPGroups[*].VirtualAddresses) scopes the
	// deny consistently regardless of mastership. The seen maps dedup against the
	// live snapshot, so on the master node (where the VIP is already live) the
	// result is byte-identical. Lifeline interfaces (fxp0/em0/fab*) are excluded,
	// mirroring the static-address path; standalone (no-VRRP) zones are untouched.
	addZoneVIP := func(zone, host string) {
		set := byZone[zone]
		if set == nil {
			set = &addrSet{seen4: map[string]bool{}, seen6: map[string]bool{}}
			byZone[zone] = set
		}
		if strings.Contains(host, ":") {
			if !set.seen6[host] {
				set.seen6[host] = true
				set.v6 = append(set.v6, host)
			}
		} else if !set.seen4[host] {
			set.seen4[host] = true
			set.v4 = append(set.v4, host)
		}
	}
	zoneByIface := buildInterfaceZoneMap(cfg)
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			if hostInboundLifelineInterface(unitName, lifelines) {
				continue
			}
			zone := zoneByIface[unitName]
			if zone == "" {
				continue
			}
			vgKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				vgKeys = append(vgKeys, k)
			}
			sort.Strings(vgKeys)
			for _, k := range vgKeys {
				vg := unit.VRRPGroups[k]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					if host := hostIPFromCIDR(vip); host != "" {
						addZoneVIP(zone, host)
					}
				}
			}
		}
	}

	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]ZoneHostInboundView, 0)
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.HostInboundTraffic == nil {
			continue // no stanza → admit-all preserved, no deny emitted
		}
		set := byZone[name]
		view := ZoneHostInboundView{
			Zone:           name,
			SystemServices: lowerTokens(zone.HostInboundTraffic.SystemServices),
			Protocols:      lowerTokens(zone.HostInboundTraffic.Protocols),
		}
		if set != nil {
			view.V4Addrs = set.v4
			view.V6Addrs = set.v6
		}
		out = append(out, view)
	}
	return out
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
		zs := ZoneSnapshot{
			Name: name,
			ID:   uint16(i + 1),
		}
		// #3070: carry the zone's host-inbound-traffic admission set onto the
		// wire so the dataplane can enforce it for host-bound (local-delivery)
		// traffic. A nil HostInboundTraffic means the zone declared no stanza:
		// HostInboundConfigured stays false and the dataplane preserves
		// admit-all for that zone.
		if zone := cfg.Security.Zones[name]; zone != nil && zone.HostInboundTraffic != nil {
			zs.HostInboundConfigured = true
			zs.HostInboundSystemServices = lowerTokens(zone.HostInboundTraffic.SystemServices)
			zs.HostInboundProtocols = lowerTokens(zone.HostInboundTraffic.Protocols)
		}
		// #3071: carry the per-zone `tcp-rst` knob to the dataplane so a
		// denied TCP flow whose ingress (from) zone has tcp-rst enabled
		// gets a TCP RST instead of a silent drop.
		if z := cfg.Security.Zones[name]; z != nil && z.TCPRst {
			zs.TCPRst = true
		}
		out = append(out, zs)
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
