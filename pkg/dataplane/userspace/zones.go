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

// hostInboundLifelineInterface reports whether the given logical interface name
// is a management / cluster-control LIFELINE that must NEVER be subjected to a
// host-inbound deny: fxp0 (out-of-band management), em0 (cluster control plane
// / heartbeat), and the fabric links (fab*). Denying host-bound traffic on
// these would strand management or break HA. fxp0 is DHCP-managed (no static
// config address) and the canonical `control` zone is `system-services { all }`
// anyway, so this is defense-in-depth on top of those facts. The base name
// (before the unit suffix) is matched so "fxp0.0" / "em0.0" are caught too.
func hostInboundLifelineInterface(name string) bool {
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base == "fxp0" || base == "em0" || strings.HasPrefix(base, "fab")
}

// BuildZoneHostInboundViews returns one ZoneHostInboundView per
// host-inbound-CONFIGURED zone (#3070), resolving each zone's firewall-local
// host addresses via the canonical interface-snapshot builder (the same
// resolution that populates the dataplane), with management/cluster-control
// lifeline interfaces (fxp0 / em0 / fab*) excluded from the address set. A zone
// that declared NO host-inbound-traffic stanza is omitted entirely (admit-all
// preserved — zero regression). A configured zone with no resolvable static
// address (e.g. a DHCP-only interface) yields an empty address set; the daemon
// emits no deny for it (cannot scope a deny without an address — fail-open is
// the safe direction for a lifeline-adjacent feature).
func BuildZoneHostInboundViews(cfg *config.Config) []ZoneHostInboundView {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	ifaceSnaps := buildInterfaceSnapshots(cfg)
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
		if snap.Zone == "" || hostInboundLifelineInterface(snap.Name) {
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
