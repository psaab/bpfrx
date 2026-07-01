package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
)

// daemon_ddns_surface_a.go: the Surface A (router/interface-address) DDNS
// reconcile loop + the address-observation layer + the per-RG HA gate (#2691
// P2, plan §5.3/§5.5/§5.6).
//
// This MIRRORS the Surface B lease loop (daemon_ddns.go): an always-on guarded
// background goroutine, 30s cadence + nudge, per-pass context timeout. It does
// NETLINK + DHCP-client-lease reads + DNS network only — it NEVER touches the
// userspace-helper control socket (the CLAUDE.md rule), so it cannot starve
// session installs or status polls.
//
// The engine itself lives in pkg/ddns (SurfaceAManager). This file supplies the
// three daemon-owned seams the engine cannot reach into: the SCOPE LIST (from
// the committed per-interface bindings + the provider catalog), the ADDRESS
// OBSERVER (netlink / pkg/dhcp.LeaseFor), and the per-RG HA GATE
// (snapshotRethMasterState). Keeping these out of pkg/ddns is the same
// dependency-inversion the LeaseParser seam uses for Surface B.

const (
	// surfaceAReconcileInterval is the Surface A poll cadence. Like the lease
	// loop it is far above the 1/s control-socket throttle (which it never
	// touches). Address changes are immediate via the nudge channel (the #1844
	// DHCP gateway/address-change hook + commit + MASTER takeover).
	surfaceAReconcileInterval = 30 * time.Second
	// surfaceAReconcileTimeout bounds one whole Surface A reconcile pass.
	surfaceAReconcileTimeout = 60 * time.Second
	// surfaceACheckIPTimeout bounds a single external check-IP fetch (#2691 P3,
	// opt-in behind-NAT source). Well under the per-pass timeout so a slow
	// checkip endpoint fails one scope, not the whole pass.
	surfaceACheckIPTimeout = 10 * time.Second
)

// runSurfaceADDNSReconcileLoop is the supervised Surface A reconcile loop. It
// runs for the daemon's lifetime (joined via wg) and exits on ctx cancel.
func (d *Daemon) runSurfaceADDNSReconcileLoop(ctx context.Context) {
	if d.surfaceA == nil {
		return
	}
	// Immediate first pass so a restart re-publishes / withdraws without
	// waiting a full tick (the durable store + current addresses drive it).
	d.runGuardedSurfaceADDNSReconcile(ctx)

	ticker := time.NewTicker(surfaceAReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.runGuardedSurfaceADDNSReconcile(ctx)
		case <-d.surfaceAReconcileNowCh:
			d.runGuardedSurfaceADDNSReconcile(ctx)
		}
	}
}

// runGuardedSurfaceADDNSReconcile dispatches one pass into a guarded goroutine
// (skip-if-in-flight), mirroring the lease loop — a hung DNS server leaks at
// most one goroutine and the loop keeps servicing ctx + the nudge channel.
func (d *Daemon) runGuardedSurfaceADDNSReconcile(ctx context.Context) {
	if d.surfaceA == nil {
		return
	}
	if !d.surfaceAReconcileInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.surfaceAReconcileInFlight.Store(false)
		d.reconcileSurfaceAOnce(ctx)
	}()
}

// reconcileSurfaceAOnce runs one Surface A reconcile pass under the node-level
// HA writer gate fast-path (the same one the lease loop uses). When the gate is
// CLOSED (BACKUP for all RGs) the node STOPS writing entirely — but it does NOT
// withdraw valid records (the peer MASTER owns them and keeps them fresh; a
// withdraw would blackhole, plan §5.6). The per-scope gate below makes the
// publish decision PER RG so a node MASTER for one RG and BACKUP for another
// publishes only its own RG's records.
func (d *Daemon) reconcileSurfaceAOnce(ctx context.Context) {
	if d.surfaceA == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.ddnsWriterGateOpen() {
		slog.Debug("ddns surface-a: skipping reconcile — node is not MASTER for any RG")
		return
	}
	scopes := d.buildSurfaceAScopes(cfg)
	rctx, cancel := context.WithTimeout(ctx, surfaceAReconcileTimeout)
	defer cancel()
	observe := d.surfaceAObserver(cfg)
	gate := d.surfaceAGate()
	// The provider catalog lets the engine REBUILD the publish backend to
	// withdraw a removed-binding record (#2691 P2 MAJOR-2) — the owned record
	// carries only the provider NAME (scope.PolicyID), so the live credentials/
	// server come from the still-committed catalog.
	var catalog map[string]*config.DDNSProvider
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		catalog = cfg.System.Services.DynamicDNS.Providers
	}
	if err := d.surfaceA.Reconcile(rctx, scopes, observe, gate, catalog); err != nil {
		slog.Warn("ddns surface-a: reconcile pass had errors (retrying next cycle)", "err", err)
	}
}

// buildSurfaceAScopes walks the committed interfaces and materializes one
// ddns.SurfaceAScope per per-interface per-family `dynamic-dns` binding (#2691
// P2, plan §5.9). It resolves the referenced provider-catalog entry, applies a
// per-binding source-address override, and attributes the scope to its owning
// redundancy group (so the per-RG HA gate keys on it). A binding with no
// hostname or an unresolved provider is SKIPPED (the commit warning already
// told the operator; runtime degrades to nothing for that scope).
func (d *Daemon) buildSurfaceAScopes(cfg *config.Config) []ddns.SurfaceAScope {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	var catalog map[string]*config.DDNSProvider
	var forced, backoff time.Duration
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		dd := cfg.System.Services.DynamicDNS
		catalog = dd.Providers
		if dd.ForcedRefreshSeconds > 0 {
			forced = time.Duration(dd.ForcedRefreshSeconds) * time.Second
		}
		if dd.ErrorBackoffMaxSeconds > 0 {
			backoff = time.Duration(dd.ErrorBackoffMaxSeconds) * time.Second
		}
	}

	var out []ddns.SurfaceAScope
	add := func(ifName string, ifc *config.InterfaceConfig, un int, family ddns.Family, b *config.InterfaceDynamicDNSConfig) {
		if b == nil {
			return
		}
		if b.Hostname == "" || b.Provider == "" {
			return
		}
		prov, ok := catalog[b.Provider]
		if !ok || prov == nil {
			slog.Debug("ddns surface-a: binding references undefined provider; skipping",
				"iface", ifName, "unit", un, "family", int(family), "provider", b.Provider)
			return
		}
		// A per-binding source-address overrides the provider's default.
		p := *prov
		if b.SourceAddress != "" {
			p.SourceAddress = b.SourceAddress
		}
		src := ddns.AddressSourceInterface
		switch b.AddressSource {
		case string(ddns.AddressSourceDHCP):
			src = ddns.AddressSourceDHCP
		case string(ddns.AddressSourceCheckIP):
			// checkip is opt-in and requires the provider to carry a checkip-url;
			// without it, fall back to interface observation (the commit warning
			// flags the missing url).
			if prov.CheckIPURL != "" {
				src = ddns.AddressSourceCheckIP
			}
		}
		ttl := b.TTLSeconds
		key := ddns.ScopeKey{
			Family:          family,
			Interface:       ifName,
			Unit:            un,
			RoutingInstance: prov.RoutingInstance,
			RGOwner:         ifc.RedundancyGroup,
			PolicyID:        b.Provider,
			// The published NAME is part of the Surface A scope identity (#2903):
			// changing the configured hostname is a NEW scope (old name withdrawn,
			// new name published) rather than an in-place overwrite that orphans the
			// old RR. The scope's FQDN must equal SurfaceAScope.FQDN below.
			FQDN: b.Hostname,
		}
		out = append(out, ddns.SurfaceAScope{
			Key:             key,
			FQDN:            b.Hostname,
			TTL:             ttl,
			Source:          src,
			Provider:        &p,
			ForcedRefresh:   forced,
			ErrorBackoffMax: backoff,
		})
	}

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for un, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			add(ifName, ifc, un, ddns.FamilyV4, unit.DynamicDNSInet)
			add(ifName, ifc, un, ddns.FamilyV6, unit.DynamicDNSInet6)
		}
	}
	return out
}

// surfaceAObserver builds the AddressObserver for one reconcile pass (plan
// §5.3). It observes a scope's CURRENT address per its configured source:
//
//   - dhcp:      pkg/dhcp.Manager.LeaseFor(linuxIfName, af) — the authoritative
//     learned WAN address (fed by the #1844 gateway-change hook as a nudge).
//   - interface: netlink address on the bound interface/unit/family, falling
//     back to the configured static address — covers static + DHCP-applied +
//     PD-derived + reth/VIP addresses.
//
// ok=false (returned by the engine's contract) means "could not observe this
// cycle" (transient) — the engine then leaves the scope untouched (no withdraw
// on a transient, the never-blackhole rule). A valid-but-Invalid Addr means
// "definitively no address" (interface down / lease gone) — the engine
// withdraws.
func (d *Daemon) surfaceAObserver(cfg *config.Config) ddns.AddressObserver {
	return func(scope ddns.SurfaceAScope) (ddns.AddressObservation, bool) {
		ifName := scope.Key.Interface
		un := scope.Key.Unit
		af4 := scope.Key.Family == ddns.FamilyV4
		var unit *config.InterfaceUnit
		if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok && ifc != nil {
			unit = ifc.Units[un]
		}
		linuxName := surfaceALinuxIfName(cfg, ifName, unit)

		switch scope.Source {
		case ddns.AddressSourceCheckIP:
			// Opt-in external check-IP source (behind-NAT deployments, #2691 P3).
			// The provider carries the checkip-url + (optionally) a bogus-IP
			// allowlist. A fetch failure is a TRANSIENT observation failure
			// (ok=false) — never a withdraw.
			if scope.Provider == nil || scope.Provider.CheckIPURL == "" {
				return ddns.AddressObservation{}, false
			}
			ctx, cancel := context.WithTimeout(context.Background(), surfaceACheckIPTimeout)
			defer cancel()
			allow, badAllow := ddns.ParseAllowlistChecked(scope.Provider.CheckIPAllowlist)
			if len(badAllow) > 0 {
				// A malformed checkip-allowlist token (operator typo) is dropped so
				// the valid entries still gate, but a silent drop shrinks the bogus-IP
				// safety gate (#2839). The commit-time warning already named the token;
				// log once per (provider, allowlist-string) so the running daemon also
				// surfaces it without flooding the per-tick observer.
				key := scope.Provider.Name + "\x00" + scope.Provider.CheckIPAllowlist
				if _, dup := d.surfaceACheckIPAllowlistWarned.LoadOrStore(key, struct{}{}); !dup {
					slog.Warn("ddns surface-a: ignoring malformed checkip-allowlist token(s); "+
						"bogus-IP allowlist is smaller than configured",
						"provider", scope.Provider.Name, "tokens", badAllow)
				}
			}
			// Bind the checkip probe to the provider's configured source-address /
			// interface / VRF (#2846) so it egresses from the same source as the
			// DDNS updates — not the kernel default route. Reuse the manager's
			// cached per-binding HTTP client (#2904) so the recurring checkip probe
			// shares the keep-alive connection pool with the DNS-update path instead
			// of rebuilding a transport every reconcile pass.
			client, berr := d.surfaceA.CheckIPClient(scope.Provider)
			if berr != nil {
				// FAIL-CLOSED (#3733): a source-address/interface/VRF WAS
				// configured for this provider but could not be honored (e.g. a
				// malformed source-address). checkip is an address oracle —
				// falling back to the kernel default route would egress via a
				// DIFFERENT WAN and return the WRONG WAN's public IP, republishing
				// the wrong-WAN class #2846 closed. CheckIPBound (below) refuses to
				// probe when berr != nil and returns ok=false: a TRANSIENT
				// observation (no publish, never a withdraw). Log once per
				// (provider, bind-error) so a persistent misconfig surfaces without
				// flooding the per-tick observer.
				key := scope.Provider.Name + "\x00" + berr.Error()
				if _, dup := d.surfaceACheckIPSourceBindWarned.LoadOrStore(key, struct{}{}); !dup {
					slog.Warn("ddns surface-a: checkip source bind unusable; "+
						"skipping probe (fail-closed, not falling back to default route)",
						"provider", scope.Provider.Name, "err", berr)
				}
			}
			a, ok := ddns.CheckIPBound(ctx, client, scope.Provider.CheckIPURL, af4, allow, berr)
			if !ok {
				return ddns.AddressObservation{}, false
			}
			return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceCheckIP}, true

		case ddns.AddressSourceDHCP:
			if d.dhcp == nil {
				return ddns.AddressObservation{}, false
			}
			af := dhcp.AFInet
			if !af4 {
				af = dhcp.AFInet6
			}
			lease := d.dhcp.LeaseFor(linuxName, af)
			if lease == nil {
				// No lease for this family yet: definitively no address. Withdraw
				// any previously-published record (the lease is gone).
				return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
			}
			a := lease.Address.Addr().Unmap()
			if !a.IsValid() {
				return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
			}
			// Public-address gate (#3732): a DHCP-learned WAN address is NOT
			// guaranteed globally routable. CGNAT (100.64/10), RFC1918, ULA
			// (fc00::/7), documentation, and other IANA special-purpose ranges
			// are all legitimately handed out over DHCP. Publishing one to a
			// public DNS provider leaks internal addressing AND points the
			// A/AAAA record at an unroutable address. The interface
			// (selectInterfaceAddr), static (staticUnitAddr), and checkip
			// (parseCheckIPBody) sources all apply this SAME ddns.IsPublicAddr
			// gate — the DHCP source was the one Surface A source that skipped
			// it. A non-public lease is a DEFINITIVE "no publishable address of
			// this family" (matching the interface source's non-public
			// handling), so the engine WITHDRAWS any previously-published
			// record rather than leaving a stale public one — never publish a
			// non-public address, never blackhole.
			if !ddns.IsPublicAddr(a) {
				slog.Warn("surface-a: skipping non-public dhcp lease address",
					"address", a.String(), "interface", linuxName)
				return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
			}
			return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceDHCP}, true

		default: // interface
			a, ok := d.observeInterfaceAddr(linuxName, af4, unit)
			if !ok {
				// netlink read failed (transient): leave the scope untouched.
				return ddns.AddressObservation{}, false
			}
			return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceInterface}, true
		}
	}
}

// surfaceALinuxIfName maps a configured interface/unit to the kernel device
// name the address lives on. RETH names resolve to the local physical member;
// the unit's VLAN id appends a ".<vlan>" sub-interface suffix (the same
// derivation pkg/dhcp keys its leases on, DHCPLeaseIfName).
func surfaceALinuxIfName(cfg *config.Config, ifName string, unit *config.InterfaceUnit) string {
	resolved := ifName
	if cfg != nil {
		resolved = cfg.ResolveReth(ifName)
	}
	return config.DHCPLeaseIfName(resolved, unit)
}

// netlinkLinkByName and netlinkAddrList are the netlink read seams for
// observeInterfaceAddr. They are package vars so tests can inject a synthetic
// link/address list (and a read FAILURE) without touching the real kernel
// netlink socket — the same dependency-inversion pattern #2294/#2775 use.
var (
	netlinkLinkByName = netlink.LinkByName
	netlinkAddrList   = netlink.AddrList
)

// observeInterfaceAddr reads the current publishable address of the given family
// on a kernel interface via netlink (selection policy in selectInterfaceAddr:
// prefer an RFC 4862 preferred address over a deprecated one, never a
// tentative/dadfailed/optimistic one, public-gated via ddns.IsPublicAddr).
//
// Contract (the engine relies on the (addr, ok) distinction, plan §5.3):
//
//   - (addr, true)  — a definitive observation. A valid addr publishes it; an
//     invalid/zero addr means "definitively no address of this family"
//     (interface present but addressless and no usable static) → the engine
//     WITHDRAWS any previously-published record.
//   - (zero, false) — the interface could NOT be read this cycle (a transient
//     LinkByName / AddrList netlink failure: interface absent during a rename,
//     reth/HA churn, a netlink hiccup). The engine leaves the scope UNTOUCHED
//     (no publish, no withdraw; retry next pass) — the never-blackhole rule.
//
// The configured static address is a fallback ONLY on the present-but-addressless
// path (the legitimate static-use case: a successful read returned no usable
// dynamic address). It is NEVER returned on a link-READ error — publishing a
// configured static when we could not read the interface at all would point DNS
// at a "configured" address that may not be "active" in the kernel data plane
// (the #2840 transient-vs-definitive distinction). On a read error we cannot
// tell present-but-addressless from absent, so the only safe answer is the
// transient (zero, false).
func (d *Daemon) observeInterfaceAddr(linuxName string, af4 bool, unit *config.InterfaceUnit) (netip.Addr, bool) {
	link, err := netlinkLinkByName(linuxName)
	if err != nil {
		// Link read failed (interface absent during a rename / reth churn /
		// netlink hiccup): we cannot distinguish present-but-addressless from
		// genuinely-down, so this is a TRANSIENT observation. Do NOT publish the
		// configured static here — return (zero, false) so the engine leaves the
		// scope untouched and retries next pass (#2840).
		return netip.Addr{}, false
	}
	family := netlink.FAMILY_V4
	if !af4 {
		family = netlink.FAMILY_V6
	}
	addrs, err := netlinkAddrList(link, family)
	if err != nil {
		// Address read failed for an otherwise-present link: still transient
		// (we did not get a definitive address list). Leave the scope untouched
		// rather than fall back to the static (#2840).
		return netip.Addr{}, false
	}
	if best, ok := selectInterfaceAddr(addrs, af4); ok {
		return best, true
	}
	// Interface read SUCCEEDED but yielded no usable dynamic address: this is the
	// legitimate present-but-addressless case. Fall back to a configured static
	// address (still gated through ddns.IsPublicAddr in staticUnitAddr).
	if a, ok := staticUnitAddr(unit, af4); ok {
		return a, true
	}
	// Interface is up but has no address of this family and no usable static:
	// definitively none → the engine withdraws.
	return netip.Addr{}, true
}

// selectInterfaceAddr chooses the address to publish from a kernel interface's
// netlink address list for the requested family. It is the pure (no-netlink-I/O)
// core of observeInterfaceAddr so the selection policy can be exercised
// directly with synthetic IFA_F_* flag combinations.
//
// Selection policy (RFC 4862 address states + the Surface A publishability gate):
//
//   - NEVER select an address whose DAD has not succeeded:
//     IFA_F_TENTATIVE (DAD in progress), IFA_F_DADFAILED (duplicate detected),
//     or IFA_F_OPTIMISTIC (RFC 4429 optimistic DAD — usable for some traffic but
//     not yet DAD-confirmed, so not safe to publish to global DNS). Publishing
//     one risks a duplicate/black-holed answer.
//   - NEVER select an RFC 4941/8981 SLAAC privacy/temporary address
//     (IFA_F_TEMPORARY, #2975). It is an outbound-only ephemeral identifier that
//     rotates on a short timer; publishing it leaks the privacy identifier and
//     black-holes inbound reachability when it rotates. The stable permanent
//     address (which privacy extensions keep for inbound service) is preferred.
//   - NEVER select a non-globally-meaningful address (loopback / link-local
//     uni+multicast / multicast / unspecified, AND every IANA special-purpose
//     range) — the SAME ddns.IsPublicAddr gate the static fallback (#2776) and
//     the checkip source use. A preferred-but-ULA address is still rejected.
//   - PREFER an RFC 4862 `preferred` address over a `deprecated` one
//     (IFA_F_DEPRECATED). A deprecated address is being phased out (renumber /
//     PD churn / privacy-address rotation) and will soon become invalid, so
//     publishing it black-holes inbound reachability. The first eligible
//     preferred address wins; a deprecated address is remembered only as a
//     fallback used IFF no preferred address exists (never blackhole — a
//     deprecated-but-still-valid address is better than no answer).
//
// netlink returns a stable order, so "first eligible" is deterministic.
func selectInterfaceAddr(addrs []netlink.Addr, af4 bool) (netip.Addr, bool) {
	deprecated := netip.Addr{}
	for _, ad := range addrs {
		ip, ok := netip.AddrFromSlice(ad.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if af4 != ip.Is4() {
			continue
		}
		// Skip addresses whose DAD has not succeeded — they may be duplicate or
		// not yet usable. tentative/dadfailed/optimistic are never publishable.
		//
		// Also skip RFC 4941/8981 SLAAC privacy/temporary addresses
		// (IFA_F_TEMPORARY, #2975). A temporary address is an outbound-only
		// ephemeral identifier that rotates on a short timer; publishing one to
		// public DNS leaks the privacy identifier AND black-holes inbound
		// reachability as soon as it rotates (the record points at an address
		// that no longer exists). The stable permanent address on the same
		// interface — which privacy extensions are designed to KEEP for inbound
		// service — is the correct publication target.
		if ad.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_OPTIMISTIC|unix.IFA_F_TEMPORARY) != 0 {
			continue
		}
		// Globally-routable-unicast gate (#2776): reject link-local, loopback,
		// unspecified, multicast, ULA, CGNAT, documentation, and every other
		// IANA special-purpose range. A preferred-but-ULA address is rejected.
		if !ddns.IsPublicAddr(ip) {
			continue
		}
		if ad.Flags&unix.IFA_F_DEPRECATED != 0 {
			// Remember the first deprecated candidate as a no-blackhole fallback.
			if !deprecated.IsValid() {
				deprecated = ip
			}
			continue
		}
		// First eligible preferred address wins.
		return ip, true
	}
	if deprecated.IsValid() {
		return deprecated, true
	}
	return netip.Addr{}, false
}

// staticUnitAddr returns the first configured static address of the given
// family on a unit (CIDR → bare addr), if any.
//
// The candidate is gated through ddns.IsPublicAddr (#2776), the SAME
// globally-routable-unicast predicate the netlink and checkip address sources
// use. Without this gate the fallback applied only a loopback/link-local/
// unspecified filter and could publish a multicast, ULA, CGNAT, documentation,
// or otherwise-reserved configured address as the router's A/AAAA record when
// the kernel interface is absent/addressless. A mis-scoped static address is
// skipped and surfaced at WARN rather than silently published (never-blackhole:
// a bad static address must not masquerade as a usable answer).
func staticUnitAddr(unit *config.InterfaceUnit, af4 bool) (netip.Addr, bool) {
	if unit == nil {
		return netip.Addr{}, false
	}
	for _, cidr := range unit.Addresses {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		a := p.Addr().Unmap()
		if a.Is4() != af4 {
			continue
		}
		if !ddns.IsPublicAddr(a) {
			slog.Warn("surface-a: skipping non-public static address",
				"address", a.String(), "cidr", cidr)
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// surfaceAGate builds the per-RG HA writer gate for one reconcile pass (#2664,
// plan §5.6). It REUSES the same per-RG master snapshot the lease loop uses. A
// scope on an RG-owned (reth) interface is writable IFF this node is MASTER for
// that RG. An RG 0 scope (a non-HA interface) is bound to RG0 — the
// control-plane redundancy group — so exactly the RG0-primary node publishes it
// (#2972). Standalone (no cluster) returns nil so the engine admits every scope.
//
// Why RG0/non-HA scopes need their own gate (#2972): unlike DHCP-lease DDNS
// (where each node's Kea memfile is rendered master-filtered per RG, so the two
// nodes' lease input sets are disjoint), Surface A scopes are built directly
// from the active config + the interface observer. BOTH nodes build the
// IDENTICAL RG0 scope. The node-level writer gate (ddnsWriterGateOpen) opens on
// ANY-RG mastership, so in active-active HA (node0 masters RG1, node1 masters
// RG2) BOTH nodes pass it AND — before this fix — both admitted every RGOwner==0
// scope, double-writing the same configured FQDN. If the two nodes observe
// different WAN addresses the public A/AAAA record flaps. Tying RGOwner==0 to
// RG0 ownership yields a single writer that follows RG0 failover.
func (d *Daemon) surfaceAGate() ddns.ScopeGate {
	if d.cluster == nil {
		return nil
	}
	master := d.snapshotRethMasterState()
	rg0Writer := d.surfaceARG0Writer(master)
	return func(s ddns.ScopeKey) bool {
		if s.RGOwner == 0 {
			return rg0Writer
		}
		return master[s.RGOwner]
	}
}

// surfaceARG0Writer reports whether THIS node is the single writer for
// RG0/non-HA Surface A scopes in a cluster (#2972). RG0 is the control-plane
// redundancy group (the config-authority group, daemon_ha.go RG0 handling):
// exactly one node is RG0 primary at any time, so binding the non-HA scopes to
// RG0 ownership gives a deterministic single writer that follows RG0 failover.
//
//   - RG0 tracked (the standard cluster, RG0 configured): the per-RG master
//     snapshot is authoritative — admit IFF this node masters RG0.
//   - RG0 NOT tracked (a non-standard cluster with only data RGs, or the brief
//     window before the first RG0 election settles): master[0] is absent. Fall
//     back to a deterministic single writer — the lowest node ID (node 0) — so
//     the non-HA scopes are still written by exactly one node and never
//     double-written. (A standalone node returns nil from surfaceAGate and never
//     reaches here.)
func (d *Daemon) surfaceARG0Writer(master map[int]bool) bool {
	if d.cluster == nil {
		return true
	}
	if isMaster, tracked := master[0]; tracked {
		return isMaster
	}
	return d.cluster.NodeID() == 0
}

// nudgeSurfaceADDNSReconcile requests an immediate Surface A reconcile pass
// (config commit / DHCP address change / MASTER takeover). Non-blocking depth-1
// send: coalesces a burst into one pending wakeup.
func (d *Daemon) nudgeSurfaceADDNSReconcile() {
	if d.surfaceAReconcileNowCh == nil {
		return
	}
	select {
	case d.surfaceAReconcileNowCh <- struct{}{}:
	default:
	}
}

// ForceDDNSUpdate is the operator force-now verb (#3276, the daemon half of
// `request system dynamic-dns update`). When force is true it arms the Surface A
// force-now latch (re-assert every owned scope's wire record on the next pass,
// bypassing change-detection + the forced-refresh floor) and nudges an immediate
// reconcile; when force is false it only nudges a re-observe/publish-if-changed
// pass (the `check` verb). Both honor the per-RG HA writer gate via the SAME
// node-level fast path the reconcile loops use: on a node that masters NO RG
// (the backup) it takes NO action and returns ok=false with a clear message, so
// the verb never double-writes from the standby (the RG owner publishes, #2972).
// A standalone node (no cluster) is always the writer. Returns (ok, message)
// for the operator surface.
func (d *Daemon) ForceDDNSUpdate(force bool) (bool, string) {
	if d.surfaceA == nil && d.ddns == nil {
		return false, "dynamic-dns: DDNS engine not running (dataplane disabled)"
	}
	// Per-RG owner gate (#2972): only a node that masters at least one RG may
	// publish. The backup must not re-assert records the peer master owns — that
	// would double-write the same FQDN (and flap the public record if the two
	// nodes observe different addresses). The per-scope gate inside Reconcile
	// further restricts a multi-RG-active node to only its own RGs' scopes.
	if !d.ddnsWriterGateOpen() {
		return false, "dynamic-dns: this node is not the active writer for any " +
			"redundancy group; the redundancy-group owner publishes (no action " +
			"taken on the backup)"
	}
	if force && d.surfaceA != nil {
		d.surfaceA.ForceRefresh()
	}
	// Nudge both DDNS reconcile loops immediately (Surface A router records and
	// the DHCP-lease Surface B path) so the forced/checked pass runs now rather
	// than waiting for the next 30s tick.
	d.nudgeSurfaceADDNSReconcile()
	d.nudgeDDNSReconcile()
	if force {
		return true, "dynamic-dns: forced an immediate update of all DDNS " +
			"records owned by this node"
	}
	return true, "dynamic-dns: triggered an immediate DDNS check on this node " +
		"(publishes only changed records)"
}

// SurfaceAStats returns the Surface A counter snapshot for the API collector /
// show command, or nil when the manager is not constructed (NoDataplane).
func (d *Daemon) SurfaceAStats() *ddns.SurfaceAStats {
	if d.surfaceA == nil {
		return nil
	}
	st := d.surfaceA.Stats()
	return &st
}

// SurfaceAStatus returns the per-scope last-published views for `show` (the
// operator surface, plan §5.5). Empty when the manager is absent.
func (d *Daemon) SurfaceAStatus() []ddns.SurfaceAStatusView {
	if d.surfaceA == nil {
		return nil
	}
	// Materialize the CURRENTLY configured scopes so the status surfaces every
	// configured scope — including ones that never published or are erroring —
	// not just the durably-owned ones (#2843). A nil cfg yields only the
	// withdraw-pending (orphaned-ownership) rows.
	var scopes []ddns.SurfaceAScope
	if cfg := d.store.ActiveConfig(); cfg != nil {
		scopes = d.buildSurfaceAScopes(cfg)
	}
	return d.surfaceA.StatusViews(scopes)
}
