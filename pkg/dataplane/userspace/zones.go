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
	Zone string
	// Interfaces lists the interface refs whose EFFECTIVE host-inbound token
	// set (zone-level ∪ interface-level override, #3362) equals this view's
	// SystemServices/Protocols. A zone with no per-interface override yields a
	// single view per zone covering all its interfaces (pre-#3362 shape); a zone
	// with an override yields one view per distinct effective token set, each
	// scoped to that set's interface addresses. Sorted; informational/test only
	// (the nft emission keys on the address set, which is per-interface).
	Interfaces     []string
	SystemServices []string
	Protocols      []string
	V4Addrs        []string // bare host IPv4 addresses (no prefix)
	V6Addrs        []string // bare host IPv6 addresses (no prefix)
}

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

// BuildZoneHostInboundViews returns one ZoneHostInboundView per configured
// security zone (#3070; #3405 default-deny parity — every zone enforces, see
// below), resolving each zone's firewall-local
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
// #3405: a zone that declared NO host-inbound-traffic stanza is NOT omitted —
// it is treated as an empty stanza and gets a catch-all DROP scoped to its
// firewall-local addresses (Junos default-deny: deny every host-bound
// service/protocol not explicitly permitted). The only no-address case left is a
// configured zone whose interfaces have neither a static config address nor any
// live kernel address yet (e.g. a DHCP WAN before its first lease, or a backup
// node before VIP install): it yields an empty address set, the daemon emits no
// deny for it, and it self-heals once an address appears because the
// lease-change / commit paths re-render. That transient fail-open admit window
// is surfaced to operators by AddresslessEnforcingZones (#3698) — the daemon
// logs a state-transition warning and exports xpf_host_inbound_addressless_zones
// while the window is open, so it is no longer silent.
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
	// #3362: per-interface host-inbound override lookup (ref → override, with
	// physical→unit expansion). The EFFECTIVE token set for an interface is the
	// UNION of its zone-level set and this override; interfaces in the same zone
	// with the SAME effective set share one view (one nft address set), so a zone
	// with NO override produces exactly one view per zone (pre-#3362 shape).
	overrideByIface := buildInterfaceHostInboundMap(cfg)

	// Each emitted view is a group keyed by (zone, effective-token signature).
	// Addresses accumulate per group; a group is created lazily on its first
	// address so a configured-but-address-less interface stays omitted (admit
	// nothing emitted, self-heals when an address appears) exactly as before.
	type group struct {
		zone   string
		svc    []string
		proto  []string
		v4, v6 []string
		seen4  map[string]bool
		seen6  map[string]bool
		ifaces map[string]bool
	}
	groups := make(map[string]*group)
	getGroup := func(zone string, svc, proto []string, iface string) *group {
		sig := zone + "\x00" + strings.Join(svc, ",") + "\x00" + strings.Join(proto, ",")
		g := groups[sig]
		if g == nil {
			g = &group{
				zone: zone, svc: svc, proto: proto,
				seen4: map[string]bool{}, seen6: map[string]bool{},
				ifaces: map[string]bool{},
			}
			groups[sig] = g
		}
		if iface != "" {
			g.ifaces[iface] = true
		}
		return g
	}
	addAddr := func(g *group, host string) {
		if strings.Contains(host, ":") {
			if !g.seen6[host] {
				g.seen6[host] = true
				g.v6 = append(g.v6, host)
			}
		} else if !g.seen4[host] {
			g.seen4[host] = true
			g.v4 = append(g.v4, host)
		}
	}
	// configured reports whether a zone enforces host-inbound at all. #3405:
	// EVERY configured security zone enforces host-inbound (Junos/vSRX
	// default-deny parity) — a zone with interfaces but NO `host-inbound-traffic`
	// stanza is treated identically to an empty stanza (`host-inbound-traffic
	// { }`): it scopes a catch-all kernel DROP to its firewall-local addresses,
	// denying every host-bound service/protocol not explicitly permitted. Before
	// #3405 a no-stanza zone was skipped entirely (admit-all), a permit-all
	// management-plane exposure on any zone the operator never locked down. The
	// management / cluster-control lifeline interfaces (fxp0/em0/fab*) are
	// excluded from the address sets below, and the established / ESP-AH / ND /
	// PMTUD accepts precede every drop, so the default-deny can never strand
	// management or break HA. A zone-level stanza or any per-interface override
	// (#3362) still further scopes what the zone admits.
	configured := func(zone *config.ZoneConfig) bool {
		return zone != nil
	}

	// Seed a zone-default group (zone-level effective tokens, no override) for
	// every configured zone so each configured zone yields at least one view —
	// even when its only interface is a lifeline (no address contributed) — the
	// pre-#3362 "one view per configured zone" contract. Non-overridden
	// interfaces accumulate their addresses into this same group (identical
	// signature); fully-overridden / address-less zones keep an empty view (the
	// daemon emits no deny for it).
	zoneNamesSorted := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNamesSorted = append(zoneNamesSorted, name)
	}
	sort.Strings(zoneNamesSorted)
	for _, name := range zoneNamesSorted {
		zone := cfg.Security.Zones[name]
		if !configured(zone) {
			continue
		}
		svc, proto := unionHostInboundTokens(zone.HostInboundTraffic, nil)
		getGroup(name, svc, proto, "")
	}

	// Per-interface static/learned addresses from the resolved snapshots.
	for _, snap := range ifaceSnaps {
		if snap.Zone == "" || hostInboundLifelineInterface(snap.Name, lifelines) {
			continue
		}
		zone := cfg.Security.Zones[snap.Zone]
		if !configured(zone) {
			continue
		}
		svc, proto := unionHostInboundTokens(zone.HostInboundTraffic, overrideByIface[snap.Name])
		var g *group
		for _, a := range snap.Addresses {
			host := hostIPFromCIDR(a.Address)
			if host == "" {
				continue
			}
			if g == nil {
				g = getGroup(snap.Zone, svc, proto, snap.Name)
			}
			addAddr(g, host)
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
	// The VIP is added to its interface's EFFECTIVE-token group (#3362), so a VIP
	// on an overridden interface is scoped by that interface's override.
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
			zoneName := zoneByIface[unitName]
			if zoneName == "" {
				continue
			}
			zone := cfg.Security.Zones[zoneName]
			if !configured(zone) {
				continue
			}
			svc, proto := unionHostInboundTokens(zone.HostInboundTraffic, overrideByIface[unitName])
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
						addAddr(getGroup(zoneName, svc, proto, unitName), host)
					}
				}
			}
		}
	}

	// Emit groups deterministically: the signature begins with the zone name,
	// so sorting by signature orders views by zone then by token set. Addresses
	// within a view are sorted for a reproducible nft payload.
	sigs := make([]string, 0, len(groups))
	for sig := range groups {
		sigs = append(sigs, sig)
	}
	sort.Strings(sigs)
	out := make([]ZoneHostInboundView, 0, len(sigs))
	for _, sig := range sigs {
		g := groups[sig]
		ifaces := make([]string, 0, len(g.ifaces))
		for name := range g.ifaces {
			ifaces = append(ifaces, name)
		}
		sort.Strings(ifaces)
		// Addresses are kept in accumulation order (static interface addresses
		// first, then VRRP VIPs) — NOT sorted — to preserve the pre-#3362 nft
		// payload ordering. Order is deterministic: snapshots come from
		// sorted-name iteration and VIPs from sorted interface/unit/group walks.
		out = append(out, ZoneHostInboundView{
			Zone:           g.zone,
			Interfaces:     ifaces,
			SystemServices: g.svc,
			Protocols:      g.proto,
			V4Addrs:        g.v4,
			V6Addrs:        g.v6,
		})
	}
	return out
}

// AddresslessEnforcingZone names a configured host-inbound-ENFORCING security
// zone that currently resolves NO firewall-local address across its non-lifeline
// interfaces (#3698). Such a zone contributes nothing to the kernel-nft
// host-inbound deny scoping (BuildZoneHostInboundViews yields an empty address
// set for it, and applyHostInboundFilter emits no deny), so host-bound packets
// to a freshly-usable address can reach the kernel input path without the zone's
// intended default-deny — a transient fail-open admit window. The window
// self-heals once an address is installed (DHCP lease / VRRP VIP / commit
// re-render), but is otherwise SILENT; this type carries the machine-readable
// signal the daemon logs and exports so the window is observable.
type AddresslessEnforcingZone struct {
	Zone string
	// Interfaces are the non-lifeline interface refs assigned to the zone
	// (exactly as authored under `security zones <z> interfaces <ref>`), sorted.
	// At least one is present — a zone whose only interfaces are management /
	// cluster-control lifelines (fxp0 / em0 / fab*) is NOT reported, since
	// lifeline traffic is intentionally never host-inbound-denied.
	Interfaces []string
}

// AddresslessEnforcingZones returns, in sorted zone order, the configured
// host-inbound-enforcing zones currently in the transient fail-open admit window
// (#3698): a zone that has at least one non-lifeline interface assigned yet
// resolves NO firewall-local address (no static config address, no live kernel
// address, no VRRP VIP). The "is this zone scoped by any address" decision is
// read back from BuildZoneHostInboundViews itself — the exact same builder that
// drives the nft emission — so this observability signal can never disagree with
// what applyHostInboundFilter actually enforces (a zone is reported iff the
// daemon emits no host-inbound deny for it).
//
// Excluded (NOT reported), so the signal stays low-noise and precise:
//   - zones that resolve any address (static / DHCP-learned / VRRP VIP) — scoped;
//   - zones whose only interfaces are lifelines (fxp0 / em0 / fab*) — lifeline
//     traffic is never denied, so there is no fail-open to surface;
//   - zones with no interfaces assigned — nothing to protect.
func AddresslessEnforcingZones(cfg *config.Config) []AddresslessEnforcingZone {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	// A zone is "scoped" iff at least one of its views carries an address — the
	// same condition applyHostInboundFilter uses (hostInboundHasEnforceableView)
	// to decide whether it emits a deny. Reusing the builder guarantees the
	// observability signal matches enforcement exactly.
	scoped := make(map[string]bool)
	for _, v := range BuildZoneHostInboundViews(cfg) {
		if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
			scoped[v.Zone] = true
		}
	}
	lifelines := hostInboundLifelineSet(cfg)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []AddresslessEnforcingZone
	for _, name := range names {
		if scoped[name] {
			continue
		}
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		ifaces := make([]string, 0, len(zone.Interfaces))
		seen := make(map[string]bool, len(zone.Interfaces))
		for _, ref := range zone.Interfaces {
			ref = strings.TrimSpace(ref)
			if ref == "" || seen[ref] || hostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			seen[ref] = true
			ifaces = append(ifaces, ref)
		}
		if len(ifaces) == 0 {
			// Only lifeline (or no) interfaces — no fail-open window to report.
			continue
		}
		sort.Strings(ifaces)
		out = append(out, AddresslessEnforcingZone{Zone: name, Interfaces: ifaces})
	}
	return out
}

// unionHostInboundTokens returns the EFFECTIVE host-inbound system-service and
// protocol token sets for an interface (#3362): the zone-level set UNION the
// per-interface override, lower-cased, trimmed, and de-duplicated, with
// zone-level tokens kept first in their original order and override-only tokens
// appended. Either argument may be nil. Junos host-inbound is additive across
// the two levels, so an interface admits a service when EITHER level lists it.
func unionHostInboundTokens(zoneHI, ifaceHI *config.HostInboundTraffic) (svc, proto []string) {
	add := func(dst *[]string, seen map[string]bool, src []string) {
		for _, t := range src {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			*dst = append(*dst, t)
		}
	}
	seenS, seenP := map[string]bool{}, map[string]bool{}
	if zoneHI != nil {
		add(&svc, seenS, zoneHI.SystemServices)
		add(&proto, seenP, zoneHI.Protocols)
	}
	if ifaceHI != nil {
		add(&svc, seenS, ifaceHI.SystemServices)
		add(&proto, seenP, ifaceHI.Protocols)
	}
	return svc, proto
}

// buildInterfaceHostInboundMap resolves per-interface host-inbound overrides
// (#3362) keyed by the interface ref as it appears on a resolved interface
// snapshot (InterfaceSnapshot.Name). A ref naming a logical unit (contains
// ".") maps ONLY itself — never a sibling unit. A ref naming a physical
// interface (no unit suffix) expands to each of its configured units, mirroring
// the physical→unit expansion in buildInterfaceZoneMap, so an override authored
// on the physical applies to every unit's snapshot. Zones and refs are walked
// in sorted order; the first writer of a given key wins (deterministic).
func buildInterfaceHostInboundMap(cfg *config.Config) map[string]*config.HostInboundTraffic {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]*config.HostInboundTraffic)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zn := range zoneNames {
		zone := cfg.Security.Zones[zn]
		if zone == nil || len(zone.InterfaceHostInbound) == 0 {
			continue
		}
		refs := make([]string, 0, len(zone.InterfaceHostInbound))
		for ref := range zone.InterfaceHostInbound {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		for _, ref := range refs {
			hib := zone.InterfaceHostInbound[ref]
			if ref == "" || hib == nil {
				continue
			}
			if _, ok := out[ref]; !ok {
				out[ref] = hib
			}
			if strings.Contains(ref, ".") {
				continue // logical unit ref: exact match only, never a sibling
			}
			if ifCfg := cfg.Interfaces.Interfaces[ref]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					un := fmt.Sprintf("%s.%d", ref, unitNum)
					if _, ok := out[un]; !ok {
						out[un] = hib
					}
				}
			}
		}
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
		// traffic.
		//
		// #3405: EVERY configured security zone is host-inbound-ENFORCING (Junos
		// default-deny parity). A zone with NO `host-inbound-traffic` stanza
		// carries HostInboundConfigured=true with EMPTY token sets, so the Rust
		// classifier inserts it into `zone_host_inbound` with an empty
		// `ZoneHostInbound` -> `admits()` returns false for every
		// service/protocol -> default-deny, identical to an empty
		// `host-inbound-traffic { }` stanza and to the kernel-nft catch-all DROP
		// (BuildZoneHostInboundViews). Before #3405 a no-stanza zone stayed
		// unconfigured (absent from the table -> `None => true` admit-all), a
		// permit-all management-plane exposure on any zone the operator never
		// locked down. The global ICMP/ND/PMTUD accepts (#3171) still precede the
		// per-zone deny on the Rust path, and lifeline interfaces (fxp0/em0/fab*)
		// never reach the AF_XDP local-delivery classifier, so the flip cannot
		// strand management or break HA.
		//
		// #3362: the zone-keyed set stays the zone-level set (possibly EMPTY ->
		// fail-closed deny-all for any interface in the zone WITHOUT an override),
		// and overridden interfaces are admitted via the per-interface ifindex map
		// (InterfaceSnapshot.HostInbound*).
		if zone := cfg.Security.Zones[name]; zone != nil {
			zs.HostInboundConfigured = true
			if zone.HostInboundTraffic != nil {
				zs.HostInboundSystemServices = lowerTokens(zone.HostInboundTraffic.SystemServices)
				zs.HostInboundProtocols = lowerTokens(zone.HostInboundTraffic.Protocols)
			}
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
