package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// junos_host_deny.go is the config-level SSOT for the #4146 kernel-nft
// enforcement of the `to-zone junos-host` DENY on the DIRECT host-bound path.
//
// A direct host-bound packet (to a firewall interface IP / VRRP VIP) is
// delivered by the Linux kernel — the XDP shim shunts local-destined packets to
// it before userspace-dp ever sees them — so the fine `to-zone junos-host`
// security policy, which historically ran only on the userspace AF_XDP
// LocalDelivery path, never applied to it (the #4146 security gap). This file
// PROJECTS the effective ordered junos-host policy program per ingress zone into
// a DROP-only, representability-gated form that the kernel `xpf_hostinbound` nft
// chain (pkg/daemon/daemon_nft.go) renders. It is deliberately in pkg/config —
// the lowest package that owns policies, zones, the address book, applications,
// schedulers and feed bindings — so the #4168 commit WARNING
// (compiler_validate_warn.go) can reuse the SAME rendered-policy decision that
// drives kernel emission, and the pkg/dataplane/userspace wrapper
// (BuildJunosHostPrograms) can layer the kernel-netdev iifname scope on top.
//
// Design invariants (see docs/research/4146-junos-host-direct-deny/plan.md):
//   - ONE effective ordered program per ingress zone, assembled in Rust's exact
//     three tiers: exact `from-zone Z to-zone junos-host` -> `from-zone any
//     to-zone junos-host` (#3090) -> applicable global `to-zone junos-host`
//     (mirrors policymatch.matchJunosHost / userspace-dp evaluate_junos_host_
//     policy_l3_aware).
//   - WHOLE-PROGRAM representability gate: if ANY contributing term (any tier)
//     is un-representable, the WHOLE program emits nothing and every one of its
//     junos-host policies keeps the #4168 warning. Never a per-term partial.
//   - DROP-only via SET-SUBTRACTION: a `deny` becomes a drop; a `permit` NEVER
//     emits a fine accept (that could re-admit a coarse-rejected service — Rust
//     poll_descriptor/mod.rs:138) — instead every later deny SUBTRACTS the
//     earlier permit's source set (`saddr != <permit-set>`), so the coarse
//     host-inbound gate stays the sole admit authority.
//   - Fine-eligible L4 domain: ESP/AH (proto 50/51) are always exempt; IKE
//     500/4500 is exempt when the ingress zone's coarse host-inbound admits ike;
//     ident-reset TCP/113 is exempt only when the zone's effective coarse verdict
//     is the RST (ident-reset set AND not all/any-service). The daemon renders
//     these as exemption rules ahead of an `application any` drop.

// junosHostSelfZone is the reserved to-zone token that names the firewall's own
// host (RE) traffic context. Mirrors policymatch.JunosHostZone.
const junosHostSelfZone = "junos-host"

// JunosHostDenyL4 is one representable L4 match fragment projected from a
// junos-host policy's `match application`. An empty JunosHostDenyProgram rule
// L4 list means the deny was `application any` (matches every protocol).
type JunosHostDenyL4 struct {
	// Proto is the IP protocol number: HostInboundProtoTCP/UDP/ICMP/ICMPv6 or a
	// bare protocol number (e.g. 47 for GRE). Never 50/51/500-bearing/113-bearing
	// for a representable deny — a deny scoped to an IPsec/ident tuple is
	// un-representable (the IPsec/ident path owns it).
	Proto uint8
	// Ports is the destination-port spec for TCP/UDP (nil = all ports).
	Ports []PortRange
	// SourcePorts is the source-port spec for TCP/UDP (nil = all).
	SourcePorts []PortRange
	// ICMPType / ICMPCode constrain an ICMP/ICMPv6 fragment (nil = any).
	ICMPType *uint8
	ICMPCode *uint8
}

// JunosHostDenyRule is one projected DROP rule for a single family. The daemon
// renders it as
//
//	iifname { <zone netdevs> } [<l4>] <fam> saddr <src> [saddr != <permit-subtract>] [<fam> daddr <dst>] drop
//
// SrcAny (no source constraint) and SrcExcluded (`saddr != Src`) mirror the
// policymatch.matchAddr family semantics; a rule is only emitted for a family
// whose positive source set is non-empty OR whose match is source-any/excluded.
// Dst*/Dst are the SAME projection applied to an explicit `match
// destination-address` (#4146 destination slice) — the host chain only ever sees
// host-destined packets, so a `daddr` predicate narrows the deny to the authored
// firewall address(es). It is NEVER the zone scope (that stays `iifname`).
type JunosHostDenyRule struct {
	Family      string // "ip" or "ip6"
	SrcAny      bool   // true => match every source (no saddr predicate)
	SrcExcluded bool   // true => `saddr != Src` (source-address-excluded)
	Src         []string
	// PermitSubtract accumulates the source CIDRs of every EARLIER permit term
	// that carves this deny (rendered as additional `saddr != <set>` predicates).
	PermitSubtract []string
	// DstAny / DstExcluded / Dst mirror Src* for `match destination-address`.
	// DstAny (the overwhelmingly common `destination-address any`) renders NO
	// daddr predicate, so an unscoped deny is byte-identical to the pre-slice
	// rule.
	DstAny      bool // true => match every destination (no daddr predicate)
	DstExcluded bool // true => `daddr != Dst` (destination-address-excluded)
	Dst         []string
	// L4 is the OR-expanded set of L4 fragments; the daemon emits one nft rule
	// per fragment. Empty means `application any` (all protocols).
	L4 []JunosHostDenyL4
}

// JunosHostDenyProgram is the effective ordered junos-host DENY program for one
// ingress zone.
type JunosHostDenyProgram struct {
	Zone string
	// InterfaceRefs are the zone's NON-lifeline interface refs (config names,
	// e.g. "reth0.50"). Informational; the actual iifname scope is IngressNetdevs.
	InterfaceRefs []string
	// IngressNetdevs is the sorted set of kernel netdev names a host-bound packet
	// on this zone arrives with — the iifname scope the daemon renders each DROP
	// rule with (JunosHostZoneIngressNetdevs). EXCLUDES lifelines and any netdev
	// shared with another zone (a cross-zone-ambiguous physical parent). Empty
	// when the zone resolves to no unambiguous non-lifeline netdev: the program
	// then emits NOTHING and its denies keep the #4168 warning — the config
	// projection gates Representable/RenderedPolicyKeys on this so the warning can
	// never be suppressed for a deny that produced no kernel rule (§8 inv-1/12).
	IngressNetdevs []string
	// Representable is false when any contributing term is un-representable; the
	// program then carries NO rules and the daemon emits nothing for the zone.
	Representable bool
	// RulesV4 / RulesV6 are the projected DROP rules in first-match order.
	RulesV4 []JunosHostDenyRule
	RulesV6 []JunosHostDenyRule
	// CoarseAdmitsIKE / CoarseIdentResets drive the daemon's fine-eligible-L4
	// exemption rules ahead of an `application any` drop (§6.6). They are true
	// iff at least one ingress netdev in the zone admits the exemption
	// (len(IKEExemptNetdevs) / len(IdentResetNetdevs) > 0) — NOT a zone-wide
	// union of every per-interface override (#5565).
	CoarseAdmitsIKE   bool
	CoarseIdentResets bool
	// IKEExemptNetdevs / IdentResetNetdevs are the SUBSET of IngressNetdevs whose
	// EFFECTIVE per-interface host-inbound set admits IKE (udp 500/4500) /
	// answers TCP/113 with a RST (#5565). The daemon scopes the IKE / ident
	// exemption shield to these netdevs instead of the whole zone iifname set, so
	// a per-INTERFACE `ike` / `ident-reset` override is never widened to a sibling
	// interface in the same zone that did not configure it. A genuinely
	// zone-level exception (authored on the zone's own host-inbound-traffic)
	// admits on every interface, so its subset equals IngressNetdevs and the
	// shield stays zone-wide (no regression). Sorted; each a subset of
	// IngressNetdevs.
	IKEExemptNetdevs  []string
	IdentResetNetdevs []string
	// HasApplicationAnyDeny is true when the program contains a rendered
	// `application any` drop, so the daemon knows to emit the IKE/ident exemption
	// shields ahead of it.
	HasApplicationAnyDeny bool
}

// JunosHostDenyProjection is the whole-config result: the per-zone programs the
// daemon renders, plus the set of junos-host policy keys that rendered an
// enforced kernel rule (so the #4168 warning is suppressed for exactly those).
type JunosHostDenyProjection struct {
	Programs           []JunosHostDenyProgram
	RenderedPolicyKeys map[string]bool
}

// JunosHostZonePairPolicyKey / JunosHostGlobalPolicyKey are the stable identity
// keys used to correlate a rendered program back to the emitting policy so the
// #4168 warning can suppress exactly the rendered ones. Both the projection and
// the warning compute the same key.
func JunosHostZonePairPolicyKey(fromZone, name string) string {
	return "zp\x00" + fromZone + "\x00" + name
}

func JunosHostGlobalPolicyKey(name string) string {
	return "gl\x00" + name
}

// junosHostTerm is one contributing policy term in an ingress zone's effective
// ordered program, carrying its representability verdict and projected match.
type junosHostTerm struct {
	key    string
	action PolicyAction
	// per-family resolved source
	srcV4, srcV6       []string
	srcAnyV4, srcAnyV6 bool
	srcExcluded        bool
	// per-family resolved destination (`match destination-address`)
	dstV4, dstV6       []string
	dstAnyV4, dstAnyV6 bool
	dstExcluded        bool
	// resolved application L4 fragments (nil => application any)
	l4            []JunosHostDenyL4
	appAny        bool
	representable bool
}

// BuildJunosHostDenyProjection projects every configured ingress zone's
// effective `to-zone junos-host` policy program into the kernel-representable
// DROP-only form. It is the SSOT consumed by both the daemon nft codegen (via
// the pkg/dataplane/userspace wrapper) and the #4168 commit warning.
func BuildJunosHostDenyProjection(cfg *Config) JunosHostDenyProjection {
	out := JunosHostDenyProjection{RenderedPolicyKeys: map[string]bool{}}
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return out
	}
	feedBound := junosHostFeedBoundNames(cfg)
	lifelines := HostInboundLifelineSet(cfg)
	// Per-zone kernel netdev iifname scope. A zone whose every non-lifeline
	// netdev is cross-zone-ambiguous resolves to an EMPTY set here — it emits no
	// kernel rule, so its denies must NOT be suppressed from the #4168 warning.
	netdevsByZone := JunosHostZoneIngressNetdevs(cfg)

	// Per-policy-key bookkeeping to decide rendered-vs-warned (§3.3): a policy is
	// rendered (warning suppressed) iff it is a DENY that applies to >=1
	// enforceable ingress zone and EVERY enforceable zone it applies to has a
	// representable program. A PERMIT is NEVER suppressed — a source-restricted
	// permit's "deny non-permitted" half is the §6.5 follow-up, not enforced in
	// this DENY slice — and a REJECT is always un-representable here.
	appliesEnforceable := map[string]int{}
	blockedByUnrep := map[string]bool{}
	actionByKey := map[string]PolicyAction{}

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
		terms := junosHostEffectiveTerms(cfg, zoneName, feedBound)
		if len(terms) == 0 {
			continue
		}
		ifaceRefs := junosHostNonLifelineRefs(zone, lifelines)
		netdevs := netdevsByZone[zoneName]
		// A deny suppresses its #4168 warning ONLY if it produces a rendered
		// kernel rule, which requires >=1 unambiguous non-lifeline netdev to scope
		// the DROP by iifname — NOT merely a non-lifeline interface REF (a ref
		// whose only netdev is a cross-zone-ambiguous shared parent emits nothing).
		enforceable := len(netdevs) > 0
		representable := true
		for _, t := range terms {
			if !t.representable {
				representable = false
				break
			}
		}
		// Also un-representable if the ingress zone answers a TCP deny with a
		// RST (tcp-rst): a silent-drop kernel rule would diverge from Junos's RST
		// verdict class (§6.2). The reject follow-up lifts this.
		if zone.TCPRst {
			representable = false
		}
		var prog JunosHostDenyProgram
		if enforceable && representable {
			// A cross-dimension permit/deny overlap (a narrow-application or
			// source-excluded permit ahead of a deny) cannot be cleanly rendered
			// as a `saddr !=` subtraction — the whole program is un-representable
			// (§5.1). junosHostProjectProgram reports this via ok=false.
			var ok bool
			prog, ok = junosHostProjectProgram(zoneName, ifaceRefs, terms)
			if !ok {
				representable = false
			}
			prog.IngressNetdevs = netdevs
			// #5565: scope the fine-eligible-L4 (IKE / ident) exemption to the
			// SPECIFIC netdevs whose effective per-interface host-inbound set
			// admits it, NOT the whole zone. A per-interface `ike`/`ident-reset`
			// override then shields only the interface that configured it; a
			// zone-level exception still covers every netdev (its subset equals
			// netdevs). The CoarseAdmits* bits follow the subsets so the daemon
			// never emits a shield with no scope.
			prog.IKEExemptNetdevs, prog.IdentResetNetdevs =
				junosHostZoneExemptNetdevs(cfg, zoneName, zone, netdevs)
			prog.CoarseAdmitsIKE = len(prog.IKEExemptNetdevs) > 0
			prog.CoarseIdentResets = len(prog.IdentResetNetdevs) > 0
		}
		// Bookkeeping for the warning.
		for _, t := range terms {
			if !enforceable {
				continue
			}
			appliesEnforceable[t.key]++
			actionByKey[t.key] = t.action
			if !representable {
				blockedByUnrep[t.key] = true
			}
		}
		if !enforceable || !representable {
			out.Programs = append(out.Programs, JunosHostDenyProgram{
				Zone:          zoneName,
				InterfaceRefs: ifaceRefs,
				Representable: false,
			})
			continue
		}
		out.Programs = append(out.Programs, prog)
	}

	for key, n := range appliesEnforceable {
		if n > 0 && !blockedByUnrep[key] && actionByKey[key] == PolicyDeny {
			out.RenderedPolicyKeys[key] = true
		}
	}
	return out
}

// junosHostNonLifelineRefs returns the zone's interface refs that are not
// management/cluster-control lifelines, sorted.
func junosHostNonLifelineRefs(zone *ZoneConfig, lifelines map[string]bool) []string {
	var refs []string
	for _, ref := range zone.Interfaces {
		if ref == "" || HostInboundLifelineInterface(ref, lifelines) {
			continue
		}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

// junosHostEffectiveTerms assembles the ingress zone's effective ordered
// junos-host term list in Rust's exact three-tier order (exact zone-pair ->
// from-any -> global), each term projected + representability-checked. It
// mirrors policymatch.matchJunosHost's tier enumeration.
func junosHostEffectiveTerms(cfg *Config, zone string, feedBound map[string]bool) []junosHostTerm {
	var terms []junosHostTerm
	add := func(key string, p *Policy) {
		if p == nil {
			return
		}
		terms = append(terms, junosHostProjectTerm(cfg, key, p, feedBound))
	}
	// Tier 1: exact `from-zone <zone> to-zone junos-host`.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != junosHostSelfZone || zpp.FromZone != zone {
			continue
		}
		for _, p := range zpp.Policies {
			add(JunosHostZonePairPolicyKey(zpp.FromZone, p.Name), p)
		}
	}
	// Tier 2: `from-zone any to-zone junos-host` (#3090).
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != junosHostSelfZone || zpp.FromZone != "any" {
			continue
		}
		for _, p := range zpp.Policies {
			add(JunosHostZonePairPolicyKey(zpp.FromZone, p.Name), p)
		}
	}
	// Tier 3: global `match to-zone junos-host`, from-zone scope gated (#3639).
	for _, p := range cfg.Security.GlobalPolicies {
		if p == nil || !IsHostToZoneScope(p.Match.ToZones) {
			continue
		}
		if !(IsWildcardZoneSet(p.Match.FromZones) || containsZone(p.Match.FromZones, zone)) {
			continue
		}
		add(JunosHostGlobalPolicyKey(p.Name), p)
	}
	return terms
}

func containsZone(zs []string, z string) bool {
	for _, v := range zs {
		if v == z {
			return true
		}
	}
	return false
}

// junosHostProjectTerm resolves one policy's match into a representable term. A
// reject action, scheduler-gated policy, feed-tainted / non-static source or
// destination, an un-reducible application, or an application scoped to an
// IPsec/ident exempt tuple all mark the term un-representable. A scoped
// `match destination-address` is representable for a DENY (rendered as a `daddr`
// predicate) but NOT for a permit — see the destination block below.
func junosHostProjectTerm(cfg *Config, key string, p *Policy, feedBound map[string]bool) junosHostTerm {
	t := junosHostTerm{key: key, action: p.Action, representable: true}
	// Reject is the §6.5 follow-up slice; scheduler-gated policies are
	// time-windowed and cannot be an always-on static rule (§6.2).
	if p.Action == PolicyReject || p.SchedulerName != "" {
		t.representable = false
	}
	// Source resolution (static-only, feed-untainted).
	v4, v6, anyV4, anyV6, ok := junosHostResolveAddrSet(cfg, p.Match.SourceAddresses, feedBound)
	if !ok {
		t.representable = false
	}
	t.srcV4, t.srcV6, t.srcAnyV4, t.srcAnyV6 = v4, v6, anyV4, anyV6
	t.srcExcluded = p.Match.SourceAddressExcluded
	// Destination resolution (static-only, feed-untainted — same gate as the
	// source). An explicit `match destination-address` on a DENY is representable:
	// the kernel `xpf_hostinbound` chain hooks the INPUT path, so every packet it
	// sees is already host-destined, and a `daddr` predicate simply narrows the
	// deny to the firewall address(es) the operator authored. A destination that
	// names no firewall address matches nothing in the chain — exactly as the
	// Rust/policymatch evaluation of that policy matches nothing — so the live
	// firewall-local address set is NOT needed to render it correctly.
	//
	// A PERMIT (or reject) with a SCOPED destination stays un-representable: a
	// permit is projected only as a `saddr !=` SUBTRACTION of later denies
	// (§5.1), which cannot express a carve that is also destination-scoped.
	// Leaving it un-representable keeps the whole-program gate conservative — the
	// zone emits nothing and every one of its policies keeps the #4168 warning —
	// rather than silently widening a later deny past the permit.
	dv4, dv6, dAnyV4, dAnyV6, dok := junosHostResolveAddrSet(cfg, p.Match.DestinationAddresses, feedBound)
	if !dok {
		t.representable = false
	}
	t.dstV4, t.dstV6, t.dstAnyV4, t.dstAnyV6 = dv4, dv6, dAnyV4, dAnyV6
	t.dstExcluded = p.Match.DestinationAddressExcluded
	if p.Action != PolicyDeny &&
		(junosHostAddrScoped(p.Match.DestinationAddresses) || p.Match.DestinationAddressExcluded) {
		t.representable = false
	}
	// Application resolution.
	l4, appAny, appOK := junosHostResolveApplications(cfg, p.Match.Applications)
	if !appOK {
		t.representable = false
	}
	t.l4, t.appAny = l4, appAny
	return t
}

// junosHostProjectProgram builds the DROP-only, set-subtracted rule lists for a
// representable ingress-zone program. ok=false when the program requires a
// cross-dimension permit/deny subtraction that cannot be cleanly rendered (a
// narrow-application or source-excluded permit ahead of a deny) — the whole
// program is then un-representable and the caller warns (§5.1).
func junosHostProjectProgram(zone string, ifaceRefs []string, terms []junosHostTerm) (JunosHostDenyProgram, bool) {
	prog := JunosHostDenyProgram{
		Zone:          zone,
		InterfaceRefs: ifaceRefs,
		Representable: true,
	}
	// Accumulated earlier-permit source sets (per family) that carve later
	// denies via `saddr !=`. A permit that permits ALL sources shadows every
	// later deny.
	var permitV4, permitV6 []string
	permitAllV4, permitAllV6 := false, false
	sawDeny := false
	for _, t := range terms {
		if t.action == PolicyPermit {
			// A permit can only be projected as a source SUBTRACTION of later
			// denies. That is faithful ONLY for an application-any, non-excluded
			// permit (its carve-out is exactly its source set on every later
			// deny's domain). A narrow-application or source-excluded permit is a
			// cross-dimension carve nft cannot express as one `saddr !=` — if any
			// deny follows it, the program is un-representable. A trailing permit
			// with no following deny renders nothing (its "deny non-permitted"
			// half is the §6.5 follow-up; that policy keeps the #4168 warning
			// because it is a PERMIT, never suppressed).
			if !t.appAny || t.srcExcluded {
				if sawDeny {
					return JunosHostDenyProgram{}, false
				}
				// No deny yet: a later deny would make this un-representable.
				// Record a poison flag by shadowing nothing but forcing the check
				// on the next deny.
				permitV4 = append(permitV4, junosHostPoison)
				permitV6 = append(permitV6, junosHostPoison)
				continue
			}
			if t.srcAnyV4 {
				permitAllV4 = true
			} else {
				permitV4 = append(permitV4, t.srcV4...)
			}
			if t.srcAnyV6 {
				permitAllV6 = true
			} else {
				permitV6 = append(permitV6, t.srcV6...)
			}
			continue
		}
		// action deny.
		sawDeny = true
		if junosHostHasPoison(permitV4) || junosHostHasPoison(permitV6) {
			return JunosHostDenyProgram{}, false
		}
		if r, ok := junosHostBuildRule("ip", t, permitV4, permitAllV4); ok {
			prog.RulesV4 = append(prog.RulesV4, r)
			if t.appAny {
				prog.HasApplicationAnyDeny = true
			}
		}
		if r, ok := junosHostBuildRule("ip6", t, permitV6, permitAllV6); ok {
			prog.RulesV6 = append(prog.RulesV6, r)
			if t.appAny {
				prog.HasApplicationAnyDeny = true
			}
		}
	}
	return prog, true
}

// junosHostPoison is a sentinel accumulated for a cross-dimension permit so a
// following deny (which cannot cleanly subtract it) forces the whole program
// un-representable.
const junosHostPoison = "\x00poison\x00"

func junosHostHasPoison(in []string) bool {
	for _, v := range in {
		if v == junosHostPoison {
			return true
		}
	}
	return false
}

// junosHostBuildRule projects one deny term to a single-family DROP rule,
// applying the earlier-permit source subtraction. Returns ok=false when the
// family's match resolves to "match nothing" (a constrained positive source or
// destination with no prefix of this family, or a degenerate `any`+excluded set)
// or when an earlier permit-all shadows it.
func junosHostBuildRule(family string, t junosHostTerm, permit []string, permitAll bool) (JunosHostDenyRule, bool) {
	if permitAll {
		// Every source is permitted ahead of this deny -> nothing to drop.
		return JunosHostDenyRule{}, false
	}
	var src, dst []string
	var srcAny, dstAny bool
	if family == "ip" {
		src, srcAny = t.srcV4, t.srcAnyV4
		dst, dstAny = t.dstV4, t.dstAnyV4
	} else {
		src, srcAny = t.srcV6, t.srcAnyV6
		dst, dstAny = t.dstV6, t.dstAnyV6
	}
	l4 := junosHostFamilyL4(family, t.l4)
	if !t.appAny && len(l4) == 0 {
		// The deny's application resolved entirely to the OTHER family (e.g. an
		// ICMPv6 app on the inet chain) -> matches nothing here.
		return JunosHostDenyRule{}, false
	}
	// #6613: an `*-excluded` whose resolved set is empty in BOTH families is not
	// "match everything" — Rust's rule_l3_matches fails CLOSED on it
	// (`!(v4_empty && v6_empty)`, userspace-dp/src/policy.rs), so projecting the
	// match-all arm here would widen the authored scope to every firewall
	// address while the dataplane denies nothing. The per-family helper cannot
	// see the other family, so the cross-family emptiness is computed here and
	// passed in. Strict commit already rejects an empty/dangling address-set,
	// but the LENIENT load / peer-sync path does not, so a config persisted by
	// an older binary reaches this projection.
	srcEmptyBoth := !t.srcAnyV4 && !t.srcAnyV6 && len(t.srcV4) == 0 && len(t.srcV6) == 0
	dstEmptyBoth := !t.dstAnyV4 && !t.dstAnyV6 && len(t.dstV4) == 0 && len(t.dstV6) == 0

	rule := JunosHostDenyRule{Family: family, L4: l4}
	matchAny, matchExcluded, set, ok := junosHostProjectAddrMatch(src, srcAny, t.srcExcluded, srcEmptyBoth)
	if !ok {
		return JunosHostDenyRule{}, false
	}
	rule.SrcAny, rule.SrcExcluded, rule.Src = matchAny, matchExcluded, set
	matchAny, matchExcluded, set, ok = junosHostProjectAddrMatch(dst, dstAny, t.dstExcluded, dstEmptyBoth)
	if !ok {
		return JunosHostDenyRule{}, false
	}
	rule.DstAny, rule.DstExcluded, rule.Dst = matchAny, matchExcluded, set
	if permitFam := junosHostDedup(permit); len(permitFam) > 0 {
		rule.PermitSubtract = permitFam
	}
	return rule, true
}

// junosHostProjectAddrMatch projects ONE family's address match — the resolved
// per-family CIDR set, that family's wildcard bit, and the `*-excluded` flag —
// into the rule's (any, excluded, set) predicate triple. ok=false means the
// match resolves to "match NOTHING" for this family, so the caller must project
// no rule at all.
//
// This is the SINGLE formula for BOTH the source and the destination dimension
// so the two can never drift. In particular the #5828 degenerate case — `any`
// (or the family-scoped `any-ipv4`/`any-ipv6`) together with `*-excluded`, i.e.
// "every address EXCEPT every address" = the empty set — must project NO rule on
// EITHER dimension. Classifying its empty concrete set as the "any" arm instead
// would invert the authored domain into an UNCONDITIONAL drop and could lock out
// all direct host-bound traffic on the ingress zone.
//
// The other arms mirror policymatch.matchAddr:
//   - constrained + excluded: match every address NOT in the set. A family with
//     no prefix in the excluded set therefore matches ALL of that family (e.g.
//     `10.0.0.0/8` + excluded drops every IPv6 address and every non-10/8 IPv4
//     one) — the intended match-all-of-opposite-family semantic.
//   - wildcard, not excluded: match everything, with no predicate rendered.
//   - constrained positive with no prefix of this family: matches nothing
//     (Junos empty-positive-set semantic).
//
// emptyBothFamilies reports that the authored match resolved to NO prefix in
// EITHER family and carries no wildcard. Combined with `excluded` that is the
// degenerate "everything except nothing" form, which Rust fails CLOSED on
// (rule_l3_matches requires !(v4_empty && v6_empty)); projecting the match-all
// arm for it would silently widen the authored scope to every firewall address
// while the dataplane denies nothing. It is unreachable via strict commit — the
// address-set member gate rejects an empty/dangling set — but reachable on the
// lenient load / peer-sync path from a config an older binary persisted.
func junosHostProjectAddrMatch(set []string, anyFam, excluded, emptyBothFamilies bool) (matchAny, matchExcluded bool, out []string, ok bool) {
	switch {
	case excluded:
		if anyFam {
			return false, false, nil, false
		}
		if emptyBothFamilies {
			// Fail CLOSED, matching Rust: project no rule at all rather than an
			// unconditional drop.
			return false, false, nil, false
		}
		return len(set) == 0, len(set) > 0, append([]string(nil), set...), true
	case anyFam:
		return true, false, nil, true
	case len(set) == 0:
		return false, false, nil, false
	default:
		return false, false, append([]string(nil), set...), true
	}
}

// junosHostFamilyL4 keeps the L4 fragments meaningful for a family (ICMP -> v4
// only, ICMPv6 -> v6 only; TCP/UDP/bare-proto -> both).
func junosHostFamilyL4(family string, l4 []JunosHostDenyL4) []JunosHostDenyL4 {
	if len(l4) == 0 {
		return nil
	}
	wantV6 := family == "ip6"
	var out []JunosHostDenyL4
	for _, f := range l4 {
		switch f.Proto {
		case HostInboundProtoICMP:
			if wantV6 {
				continue
			}
		case HostInboundProtoICMPv6:
			if !wantV6 {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// junosHostResolveAddrSet resolves a policy source/destination token list to
// static per-family CIDR sets. ok=false when any token (or nested member) is
// feed-tainted, resolves through a wildcard/dns-name/range address (Value ""),
// or names an unknown book entry. any* is true when a wildcard token widens the
// family to match-all.
func junosHostResolveAddrSet(cfg *Config, tokens []string, feedBound map[string]bool) (v4, v6 []string, anyV4, anyV6, ok bool) {
	ok = true
	if len(tokens) == 0 {
		return nil, nil, true, true, true
	}
	ab := cfg.Security.AddressBook
	seen4 := map[string]bool{}
	seen6 := map[string]bool{}
	addCIDR := func(val string) {
		val = strings.TrimSpace(val)
		if val == "" {
			ok = false
			return
		}
		if val == "any" || val == "any-ipv4" || val == "any-ipv6" {
			switch val {
			case "any":
				anyV4, anyV6 = true, true
			case "any-ipv4":
				anyV4 = true
			case "any-ipv6":
				anyV6 = true
			}
			return
		}
		pfx, perr := netip.ParsePrefix(val)
		if perr != nil {
			if a, aerr := netip.ParseAddr(val); aerr == nil {
				pfx = netip.PrefixFrom(a, a.BitLen())
			} else {
				ok = false
				return
			}
		}
		s := pfx.Masked().String()
		if pfx.Addr().Is6() {
			if !seen6[s] {
				seen6[s] = true
				v6 = append(v6, s)
			}
		} else if !seen4[s] {
			seen4[s] = true
			v4 = append(v4, s)
		}
	}
	for _, tok := range tokens {
		switch tok {
		case "", "any":
			anyV4, anyV6 = true, true
			continue
		case "any-ipv4":
			anyV4 = true
			continue
		case "any-ipv6":
			anyV6 = true
			continue
		}
		if junosHostNameFeedTainted(ab, feedBound, tok, map[string]bool{}) {
			ok = false
			continue
		}
		if ab != nil {
			if a, found := ab.Addresses[tok]; found {
				addCIDR(a.Value)
				continue
			}
			if _, found := ab.AddressSets[tok]; found {
				names, err := ExpandAddressSet(tok, ab)
				if err != nil {
					ok = false
					continue
				}
				for _, n := range names {
					if a, f := ab.Addresses[n]; f {
						addCIDR(a.Value)
					} else {
						ok = false
					}
				}
				continue
			}
		}
		// Not a book name: try a literal prefix/IP.
		addCIDR(tok)
	}
	return v4, v6, anyV4, anyV6, ok
}

// junosHostAddrScoped reports whether a token list names a concrete (non-any)
// address scope.
func junosHostAddrScoped(tokens []string) bool {
	for _, t := range tokens {
		switch t {
		case "", "any", "any-ipv4", "any-ipv6":
			continue
		}
		return true
	}
	return false
}

// junosHostNameFeedTainted reports whether an address token, or ANY nested
// address-set member, is bound to a dynamic feed (so its resolved set is not
// commit-stable and cannot be a static nft rule, §6.2). A name may be
// SIMULTANEOUSLY static and feed-backed, so the whole closure is inspected.
func junosHostNameFeedTainted(ab *AddressBook, feedBound map[string]bool, name string, visited map[string]bool) bool {
	if feedBound[name] {
		return true
	}
	if ab == nil || visited[name] {
		return false
	}
	set, ok := ab.AddressSets[name]
	if !ok {
		return false
	}
	visited[name] = true
	defer delete(visited, name)
	for _, m := range set.Addresses {
		if junosHostNameFeedTainted(ab, feedBound, m, visited) {
			return true
		}
	}
	for _, s := range set.AddressSets {
		if junosHostNameFeedTainted(ab, feedBound, s, visited) {
			return true
		}
	}
	return false
}

// junosHostFeedBoundNames returns the set of address-names bound to any dynamic
// feed (config-knowable membership; the live feed CONTENT is irrelevant to
// representability — a feed-bound name is never commit-stable).
func junosHostFeedBoundNames(cfg *Config) map[string]bool {
	out := map[string]bool{}
	for name := range cfg.Security.DynamicAddress.AddressBindings {
		out[name] = true
	}
	return out
}

// junosHostResolveApplications reduces a policy `match application` token list to
// OR-expanded L4 fragments. appAny is true for `any`/empty (match every
// protocol). ok=false when any application is un-resolvable, multi-term, ALG,
// protocol-less, has a non-numeric port, or is scoped to an IPsec/ident exempt
// tuple (which the IPsec/ident path owns — §6.6).
func junosHostResolveApplications(cfg *Config, tokens []string) (l4 []JunosHostDenyL4, appAny, ok bool) {
	ok = true
	if len(tokens) == 0 {
		return nil, true, true
	}
	for _, tok := range tokens {
		switch tok {
		case "", "any":
			appAny = true
			continue
		}
		// #5677: resolve a user/predefined APPLICATION first, so a user
		// application shadowing a same-named application-set keeps ITS OWN
		// ports on this direct host-bound projection. Only OR-expand as an
		// application-set when the token is NOT an application — mirroring the
		// app-first precedence of resolveUserspaceApplicationNames and the
		// #5629/#5664 policy-match / NAT / catalog fixes. Consulting the
		// application-SET table first (the pre-#5677 bug) mis-resolved a
		// shadowed user application to the set's members, so the kernel
		// direct-host DENY projected the wrong ports.
		_, isApp := ResolveApplication(tok, cfg.Applications.Applications)
		if _, isSet := ResolveApplicationSet(tok, cfg.Applications.ApplicationSets); !isApp && isSet {
			members, err := ExpandApplicationSet(tok, &cfg.Applications)
			if err != nil {
				ok = false
				continue
			}
			for _, m := range members {
				if frags, mok := junosHostReduceApp(cfg, m); mok {
					l4 = append(l4, frags...)
				} else {
					ok = false
				}
			}
			continue
		}
		if frags, aok := junosHostReduceApp(cfg, tok); aok {
			l4 = append(l4, frags...)
		} else {
			ok = false
		}
	}
	if appAny {
		// `application any` present -> the whole match is all-protocols; drop any
		// narrow fragments accumulated alongside it (any subsumes them).
		return nil, true, ok
	}
	return l4, false, ok
}

// junosHostReduceApp reduces a single application to L4 fragments. Rejects
// multi-term apps (MixedDirectTermApps), ALG-bearing apps, protocol-less apps,
// non-numeric ports, and apps scoped to an IPsec/ident exempt tuple.
func junosHostReduceApp(cfg *Config, name string) ([]JunosHostDenyL4, bool) {
	for _, mixed := range cfg.Applications.MixedDirectTermApps {
		if mixed == name {
			return nil, false
		}
	}
	app, ok := ResolveApplication(name, cfg.Applications.Applications)
	if !ok || app == nil {
		return nil, false
	}
	if app.ALG != "" {
		return nil, false
	}
	proto := strings.ToLower(strings.TrimSpace(app.Protocol))
	if proto == "" {
		return nil, false
	}
	var frag JunosHostDenyL4
	switch proto {
	case "tcp":
		frag.Proto = HostInboundProtoTCP
	case "udp":
		frag.Proto = HostInboundProtoUDP
	case "icmp":
		frag.Proto = HostInboundProtoICMP
		frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
	case "icmp6", "icmpv6", "icmp-v6":
		frag.Proto = HostInboundProtoICMPv6
		frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
	default:
		n, err := strconv.Atoi(proto)
		if err != nil || n < 0 || n > 255 {
			return nil, false
		}
		frag.Proto = uint8(n)
	}
	if frag.Proto == HostInboundProtoTCP || frag.Proto == HostInboundProtoUDP {
		dp, dok := junosHostParsePorts(app.DestinationPort)
		if !dok {
			return nil, false
		}
		sp, sok := junosHostParsePorts(app.SourcePort)
		if !sok {
			return nil, false
		}
		frag.Ports, frag.SourcePorts = dp, sp
	}
	// A deny scoped to an IPsec/ident exempt tuple can't be faithfully modeled by
	// the DENY slice (the IPsec passthrough / ident-reset path owns it, §6.6).
	if junosHostFragIsExemptTuple(frag) {
		return nil, false
	}
	return []JunosHostDenyL4{frag}, true
}

// junosHostFragIsExemptTuple reports whether an L4 fragment collides with a
// pre-fine exempt class: raw ESP/AH (proto 50/51), IKE/NAT-T (udp 500/4500), or
// ident (tcp 113).
func junosHostFragIsExemptTuple(f JunosHostDenyL4) bool {
	switch f.Proto {
	case 50, 51:
		return true
	case HostInboundProtoUDP:
		return junosHostPortsInclude(f.Ports, 500) || junosHostPortsInclude(f.Ports, 4500)
	case HostInboundProtoTCP:
		return junosHostPortsInclude(f.Ports, 113)
	}
	return false
}

func junosHostPortsInclude(ports []PortRange, p uint16) bool {
	if len(ports) == 0 {
		return true // no port constraint => all ports => includes p
	}
	for _, r := range ports {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

// junosHostParsePorts parses a Junos port spec into PortRange(s). "" => nil (all
// ports). Only numeric single ports and "lo-hi" ranges are representable; a
// named alias returns ok=false.
func junosHostParsePorts(spec string) ([]PortRange, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, true
	}
	var out []PortRange
	for _, part := range strings.Fields(spec) {
		if lo, hi, found := strings.Cut(part, "-"); found {
			l, lerr := strconv.Atoi(strings.TrimSpace(lo))
			h, herr := strconv.Atoi(strings.TrimSpace(hi))
			if lerr != nil || herr != nil || l < 0 || h > 65535 || l > h {
				return nil, false
			}
			out = append(out, PortRange{Lo: uint16(l), Hi: uint16(h)})
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 65535 {
			return nil, false
		}
		out = append(out, PortRange{Lo: uint16(v), Hi: uint16(v)})
	}
	return out, true
}

// junosHostSvcAdmitsIKE reports whether an EFFECTIVE per-interface host-inbound
// system-services set coarse-admits IKE/NAT-T (udp 500/4500) — the `ike`/`ipsec`
// token or a full admit.
func junosHostSvcAdmitsIKE(svc []string) bool {
	for _, s := range svc {
		// Match enforcement, which lower-cases every token before admitting
		// (unionHostInboundTokens/lowerTokens in pkg/dataplane/userspace, the
		// Rust classify_system_service). The sibling protocol path in this file
		// already normalizes (junosHostReduceApp, line ~776); the service path must
		// too or a lenient-loaded upper-case `IKE`/`IPSEC`/`ALL` is admitted by
		// enforcement yet missed here, so the coarse `application any` shield
		// drops the very IKE/NAT-T it was supposed to exempt (#5557).
		s = strings.ToLower(strings.TrimSpace(s))
		if HostInboundFullAdmitService(s) {
			return true
		}
		// #3226: `all` is no longer a full admit — it EXPANDS to the named
		// system-service union, which contains `ike`/`ipsec` (udp 500/4500).
		// Walk the expansion rather than string-comparing the authored token,
		// or an `all` zone loses its IKE exemption here while enforcement still
		// admits IKE, and the coarse `application any` shield drops the very
		// IKE/NAT-T it exists to exempt — the #5565 failure mode, reopened.
		for _, e := range HostInboundServiceTokenExpansion(s) {
			if e == "ike" || e == "ipsec" {
				return true
			}
		}
	}
	return false
}

// junosHostZoneExemptNetdevs returns the subset of `netdevs` (a zone's rendered
// ingress iifname scope from JunosHostZoneIngressNetdevs) whose EFFECTIVE
// per-interface host-inbound set admits IKE (udp 500/4500) and, separately, the
// subset that answers TCP/113 with a RST (ident-reset). It is the #5565 fix for
// the earlier zone-wide projection, which unioned every per-interface override
// into a single bit and widened a per-interface `ike`/`ident-reset` exception to
// every interface in the zone.
//
// A netdev admits IKE / RSTs ident if ANY interface ref whose host-bound traffic
// arrives on it (its own logical unit, or — for a VLAN subunit riding a physical
// parent — the parent) admits it. The union mirrors the coarse host-inbound gate
// (which keys on the interface's effective set, InterfaceHostInboundEffective) so
// the shield never false-denies a configured per-interface override, while a
// sibling interface that configured no exception is left out of the subset. A
// genuinely zone-level exception (authored on the zone's own
// host-inbound-traffic) is folded into every interface's effective set, so its
// subset equals `netdevs` and the shield stays zone-wide.
//
// The netdev→ref row walk mirrors JunosHostZoneIngressNetdevs exactly (physical
// row + one row per unit, plus the physical parent for a VLAN subunit) so the
// two agree on which ref feeds which netdev; results are filtered to `netdevs`
// so a cross-zone-ambiguous parent excluded from the iifname scope is never
// shielded.
func junosHostZoneExemptNetdevs(cfg *Config, zoneName string, zone *ZoneConfig, netdevs []string) (ikeNetdevs, identNetdevs []string) {
	if cfg == nil || zone == nil || len(netdevs) == 0 {
		return nil, nil
	}
	keep := make(map[string]bool, len(netdevs))
	for _, nd := range netdevs {
		keep[nd] = true
	}
	// Per-netdev accumulation of the effective coarse verdict across every
	// interface ref whose host-bound traffic arrives on it.
	type verdict struct{ ike, ident, fullAdmit bool }
	byNetdev := make(map[string]*verdict, len(netdevs))
	note := func(nd, ref string) {
		if nd == "" || !keep[nd] {
			return
		}
		svc, _, _ := zone.InterfaceHostInboundEffective(ref)
		v := byNetdev[nd]
		if v == nil {
			v = &verdict{}
			byNetdev[nd] = v
		}
		if junosHostSvcAdmitsIKE(svc) {
			v.ike = true
		}
		for _, s := range svc {
			// Case-fold to match enforcement (see junosHostSvcAdmitsIKE): a
			// lenient-loaded upper-case `ALL`/`IDENT-RESET` must set the same
			// coarse verdict here as the dataplane/Rust classifier reaches, or
			// the shield diverges from what is actually admitted (#5557).
			s = strings.ToLower(strings.TrimSpace(s))
			if HostInboundFullAdmitService(s) {
				v.fullAdmit = true
			}
			// #3226: walk the expansion so `all` — which now stands for the
			// named-service union INCLUDING ident-reset — still marks the
			// netdev as answering TCP/113 with a RST. Comparing the authored
			// token alone would silently drop the ident-reset exception on
			// every `all` zone the moment `all` stopped being a full admit.
			for _, e := range HostInboundServiceTokenExpansion(s) {
				if e == "ident-reset" {
					v.ident = true
				}
			}
		}
	}
	zoneByIface := junosHostZoneByInterface(cfg)
	addRow := func(name, own, parent string, vlan int) {
		if zoneByIface[name] != zoneName {
			return
		}
		note(own, name)
		if vlan != 0 && parent != "" {
			note(parent, name)
		}
	}
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
		addRow(ifName, junosHostLinuxName(cfg, ifName, nil), "", 0)
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			addRow(unitName, junosHostLinuxName(cfg, ifName, unit),
				junosHostLinuxName(cfg, ifName, nil), unit.VlanID)
		}
	}
	// Emit subsets in the sorted netdevs order for a deterministic iifname set.
	for _, nd := range netdevs {
		v := byNetdev[nd]
		if v == nil {
			continue
		}
		if v.ike {
			ikeNetdevs = append(ikeNetdevs, nd)
		}
		if v.ident && !v.fullAdmit {
			identNetdevs = append(identNetdevs, nd)
		}
	}
	return ikeNetdevs, identNetdevs
}

// JunosHostZoneIngressNetdevs returns, per security zone, the sorted set of
// kernel netdev names a host-bound packet on that zone arrives with — the
// iifname scope for the zone's #4146 junos-host DROP rules. It EXCLUDES
// lifelines and any netdev claimed by MORE THAN ONE zone (an ambiguous shared
// physical parent — e.g. a zone on a trunk's untagged unit-0 while the SAME
// parent carries other zones' tagged VLAN subunits), so a zone's deny can never
// over-fire on another zone's ingress.
//
// It is the SSOT for the iifname scope: the dataplane BuildJunosHostPrograms
// consumes JunosHostDenyProgram.IngressNetdevs (populated from this) for kernel
// emission, AND BuildJunosHostDenyProjection gates a deny's warning-suppression
// on a NON-EMPTY result here — so the #4168 warning can never be suppressed for
// a deny that produced no kernel rule (the F1 fix; §8 inv-1/12). The
// netdev-name resolution mirrors the dataplane interface-snapshot LinuxName
// (userspace.snapshotLinuxName) exactly, pinned byte-for-byte by
// TestJunosHostZoneNetdevsMatchSnapshot so the two planes cannot drift.
func JunosHostZoneIngressNetdevs(cfg *Config) map[string][]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	zoneByIface := junosHostZoneByInterface(cfg)
	cand := map[string]map[string]bool{}   // zone -> netdev set
	claims := map[string]map[string]bool{} // netdev -> zone set
	addCand := func(zone, nd string) {
		if zone == "" || nd == "" {
			return
		}
		if cand[zone] == nil {
			cand[zone] = map[string]bool{}
		}
		cand[zone][nd] = true
		if claims[nd] == nil {
			claims[nd] = map[string]bool{}
		}
		claims[nd][zone] = true
	}
	// One "row" per physical interface + one per unit, mirroring the dataplane
	// interface snapshot: the row's own netdev is the candidate, plus (for a VLAN
	// subunit whose frames ride the physical parent) the parent netdev.
	addRow := func(name, own, parent string, vlan int) {
		if HostInboundLifelineInterface(name, lifelines) {
			return
		}
		zone := zoneByIface[name]
		if zone == "" {
			return
		}
		addCand(zone, own)
		if vlan != 0 && parent != "" {
			addCand(zone, parent)
		}
	}
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
		addRow(ifName, junosHostLinuxName(cfg, ifName, nil), "", 0)
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			addRow(unitName, junosHostLinuxName(cfg, ifName, unit),
				junosHostLinuxName(cfg, ifName, nil), unit.VlanID)
		}
	}
	out := map[string][]string{}
	for zone, nds := range cand {
		var keep []string
		for nd := range nds {
			if len(claims[nd]) == 1 { // unambiguous: only this zone claims nd
				keep = append(keep, nd)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			out[zone] = keep
		}
	}
	return out
}

// junosHostLinuxName resolves an interface ref to its kernel netdev name,
// mirroring userspace.snapshotLinuxName EXACTLY (VLAN subunit -> parent.vlanid,
// reth unit resolution, tunnel name map, physical passthrough). Kept here so the
// #4146 iifname scope can be resolved purely from config (the dataplane consumes
// the result via JunosHostDenyProgram.IngressNetdevs); TestJunosHostZoneNetdevs
// MatchSnapshot pins it against the snapshot.
//
// The secure-tunnel arm is NOT mirrored — it is SHARED
// (Config.SecureTunnelUnitNetdev, xfrmi.go). #6691: that rule cannot be
// re-derived here, because the netdev depends on the authored bind-interface
// string rather than on the ref, and this function does not otherwise read the
// IPsec config at all. A mirrored copy of it drifted once already and left a
// junos-host deny scoped to a nonexistent netdev; the remaining arms are still
// mirrors, held by the parity test, which now carries a secure-tunnel case.
func junosHostLinuxName(cfg *Config, ifName string, unit *InterfaceUnit) string {
	if unit != nil {
		// #6691: a secure-tunnel unit's netdev is resolved from the AUTHORED
		// bind-interface, NOT by the unit-zero collapse below. Both this and
		// snapshotLinuxName call the one resolver rather than restating the
		// rule — restating it is how the iifname scope of a junos-host deny
		// came to name `st0` while the decrypted traffic arrived on `st0.0`,
		// leaving the deny unable to fire. Placed FIRST, matching
		// ResolveKernelIfName's ordering (the st rule precedes the tunnel-name
		// map there too).
		if dev, ok := cfg.SecureTunnelUnitNetdev(fmt.Sprintf("%s.%d", ifName, unit.Number)); ok {
			return dev
		}
		if tunnelNames := cfg.TunnelNameMap(); len(tunnelNames) > 0 {
			ref := fmt.Sprintf("%s.%d", ifName, unit.Number)
			if linuxName, ok := tunnelNames[ref]; ok && linuxName != "" {
				return linuxName
			}
		}
		if unit.VlanID > 0 {
			return fmt.Sprintf("%s.%d", LinuxIfName(cfg.ResolveReth(ifName)), unit.VlanID)
		}
		if strings.HasPrefix(ifName, "reth") {
			if unit.Number == 0 {
				return LinuxIfName(cfg.ResolveReth(ifName))
			}
			return LinuxIfName(cfg.ResolveReth(fmt.Sprintf("%s.%d", ifName, unit.Number)))
		}
		if unit.Number == 0 {
			return LinuxIfName(ifName)
		}
		return LinuxIfName(fmt.Sprintf("%s.%d", ifName, unit.Number))
	}
	if strings.HasPrefix(ifName, "reth") {
		return LinuxIfName(cfg.ResolveReth(ifName))
	}
	return LinuxIfName(ifName)
}

// junosHostZoneByInterface maps every interface ref (physical, base, and each
// unit) to its security zone, mirroring userspace.buildInterfaceZoneMap so the
// netdev resolution above assigns the same zone the dataplane snapshot does.
func junosHostZoneByInterface(cfg *Config) map[string]string {
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
			// #5878 phase 2: bind on the canonical logical-unit identity so this
			// mirror resolves ge-0/0/0.01 to the same runtime unit (ge-0/0/0.1)
			// the dataplane snapshot does — the consumer looks this map up by the
			// canonical "%s.%d" unit name.
			iface := CanonicalInterfaceUnitRef(rawIface)
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

func junosHostDedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
