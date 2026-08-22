package config

import (
	"fmt"
	"sort"
	"strings"
)

// host_inbound_dhcp_scope_6519.go implements the #6519 parity advisory for the
// DHCP/BOOTP exception in Junos's host-inbound model.
//
// Juniper, Security Zones (security-zone-configuration): "All services (except
// DHCP and BOOTP) can be configured either per zone or per interface. A DHCP
// server is configured only per interface because the incoming interface must
// be known by the server to be able to send out DHCP replies."
//
// So `dhcp` and `bootp` are the two host-inbound system-services Junos does NOT
// accept at the zone level. xpf accepts them there and lets them authorize every
// member interface of the zone, which is an over-authorization relative to
// Junos: a single zone-level token opens udp/67-68 on firewall-local addresses
// the operator would have had to admit interface by interface.
//
// This file WARNS; it does not change enforcement. Withdrawing the zone-level
// authorization is a NARROWING with a real population — configs in this repo
// (test/incus/xpf-cluster-fw{0,1}.conf, docs/ha-cluster*.conf) author zone-level
// `dhcp` today — and the traffic it would stop is not only a DHCP server's: the
// firewall's own DHCP CLIENT on a zoned, non-lifeline interface needs udp/68
// admitted for its unicast renewals, so a silent flip would cost that interface
// its address rather than merely refuse a service. #6519 asks for the staged
// treatment (advisory, then an all-planes flip in its own release) and this is
// the advisory stage.

// hostInboundDHCPExceptionServices are the two `system-services` tokens Junos
// documents as per-INTERFACE only. `dhcpv6` is deliberately NOT here: the
// vendor sentence names DHCP and BOOTP, and extending it to the v6 token would
// be an inference, not a citation.
var hostInboundDHCPExceptionServices = []string{"dhcp", "bootp"}

// InterfaceHostInboundOverride returns the INTERFACE-LEVEL host-inbound tokens
// that apply to ref in this zone — the union of a physical-parent override and
// ref's own unit-level override (#3720, both are interface-level statements) —
// and whether ref declares any interface-level stanza at all.
//
// It is the interface-level half of what InterfaceHostInboundEffective resolves
// — that resolver CALLS this, so the #3720 physical∪unit walk exists once and not
// twice: a divergence between them would always be a bug. It is exposed on its
// own because a caller sometimes needs to know what the INTERFACE authorized as
// distinct from what the interface ends up admitting. #6519 is that caller: "the zone-level token is what authorizes DHCP here" is precisely
// "the effective set admits it and the interface's own stanza does not", and
// that predicate is correct whether the two levels union or the interface level
// replaces the zone level.
//
// declared is stanza PRESENCE, matching InterfaceHostInboundEffective's
// overridden: a present-but-empty stanza declares an interface-level policy (of
// admitting nothing) and returns declared=true with empty token lists.
func (z *ZoneConfig) InterfaceHostInboundOverride(ref string) (svc, proto []string, declared bool) {
	if z == nil {
		return nil, nil, false
	}
	if base, unit, ok := strings.Cut(ref, "."); ok && unit != "" && base != "" {
		if phys := z.InterfaceHostInbound[base]; phys != nil {
			svc = UnionHostInboundTokens(svc, phys.SystemServices)
			proto = UnionHostInboundTokens(proto, phys.Protocols)
			declared = true
		}
	}
	if exact := z.InterfaceHostInbound[ref]; exact != nil {
		svc = UnionHostInboundTokens(svc, exact.SystemServices)
		proto = UnionHostInboundTokens(proto, exact.Protocols)
		declared = true
	}
	return svc, proto, declared
}

// hostInboundSetAdmitsService reports whether an authored `system-services` list
// admits token, walking the `all` expansion so a zone that opened `all` is
// recognized as admitting dhcp exactly as the enforcement path does (`all`
// expands to the named-service union, which includes dhcp and bootp). Case
// -insensitive, matching every other host-inbound membership predicate.
func hostInboundSetAdmitsService(svcs []string, token string) bool {
	for _, s := range svcs {
		for _, e := range HostInboundServiceTokenExpansion(strings.ToLower(strings.TrimSpace(s))) {
			if strings.ToLower(strings.TrimSpace(e)) == token {
				return true
			}
		}
	}
	return false
}

// hostInboundZoneLevelDHCPTokens returns the DHCP-exception tokens a ZONE-LEVEL
// system-services list admits, each paired with how it got there — named
// outright, or pulled in by `all`. The distinction is what makes the advisory
// actionable: "you wrote dhcp at the zone level" and "your zone-level `all`
// silently includes dhcp" need different edits, and an advisory that reported
// only the first would leave the `all` case as a silent deviation.
func hostInboundZoneLevelDHCPTokens(zoneSvc []string) []string {
	named := make(map[string]bool, len(zoneSvc))
	viaAll := false
	for _, s := range zoneSvc {
		t := strings.ToLower(strings.TrimSpace(s))
		if t == "all" {
			viaAll = true
			continue
		}
		named[t] = true
	}
	var out []string
	for _, tok := range hostInboundDHCPExceptionServices {
		switch {
		case named[tok]:
			out = append(out, tok)
		case viaAll:
			out = append(out, tok+" (via `all`)")
		}
	}
	return out
}

// validateHostInboundZoneLevelDHCPWarnings emits the #6519 commit-time advisory:
// a zone whose ZONE-LEVEL host-inbound-traffic admits `dhcp` or `bootp` — named
// outright or via `all` — thereby authorizes DHCP/BOOTP on member interfaces
// that never asked for it, which Junos does not allow to be expressed at the
// zone level at all.
//
// One advisory per zone, naming the tokens and the member interfaces the
// zone-level authorization actually reaches. An interface is reached when its
// EFFECTIVE set admits the token but its OWN interface-level stanza does not —
// i.e. the zone-level token is the authorizer. Stating it that way keeps the
// advisory correct both while the two levels union and after #6515 makes the
// interface level replace the zone level, without asserting which rule is in
// force.
//
// Lifeline interfaces (fxp0 / em0 / fab* and the configured control + fabric
// links) are skipped: they are excluded from host-inbound deny scoping entirely,
// so no zone token decides anything on them and naming them would be a false
// alarm. A zone whose reached-interface set is empty draws no advisory.
//
// WARN-only. See the file header for why the enforcement flip is staged
// separately.
func validateHostInboundZoneLevelDHCPWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	serverRefs := hostInboundDHCPServerRefs(cfg)
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []string
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.HostInboundTraffic == nil {
			continue
		}
		toks := hostInboundZoneLevelDHCPTokens(zone.HostInboundTraffic.SystemServices)
		if len(toks) == 0 {
			continue
		}
		refs := make([]string, 0, len(zone.Interfaces))
		seen := make(map[string]bool, len(zone.Interfaces))
		for _, ref := range zone.Interfaces {
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		var reached []string
		var anyClient, anyIdle bool
		for _, ref := range refs {
			if HostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			effSvc, _, _ := zone.InterfaceHostInboundEffective(ref)
			ownSvc, _, _ := zone.InterfaceHostInboundOverride(ref)
			for _, tok := range hostInboundDHCPExceptionServices {
				if hostInboundSetAdmitsService(effSvc, tok) &&
					!hostInboundSetAdmitsService(ownSvc, tok) {
					// #6519 stage 1.5: name WHY the token is load-bearing here.
					// The role is the discriminator the deferred enforcement
					// flip turns on, so the advisory computes it rather than
					// leaving every reader to work it out per interface.
					roles := hostInboundDHCPRolesFor(cfg, serverRefs, ref)
					anyClient = anyClient || roles.client
					anyIdle = anyIdle || (!roles.client && !roles.server)
					reached = append(reached,
						fmt.Sprintf("%s (%s)", ref, hostInboundDHCPRoleLabel(roles)))
					break
				}
			}
		}
		if len(reached) == 0 {
			continue
		}
		msg := fmt.Sprintf(
			"zone %q host-inbound-traffic: system-services %s %s configured at the "+
				"ZONE level, which Junos does not allow — DHCP and BOOTP are the "+
				"host-inbound services Junos accepts only per interface, because the "+
				"server must know the incoming interface to send replies. Here the "+
				"zone-level token authorizes DHCP/BOOTP on %s, which Junos would "+
				"require you to admit interface by interface. Move the token to "+
				"`interfaces <if> host-inbound-traffic system-services ...` on the "+
				"interfaces that need it — and note a per-interface stanza REPLACES "+
				"the zone stanza (#6515), so restate the zone's other tokens there or "+
				"they stop being admitted on that interface.",
			name, strings.Join(toks, ", "), pluralIsAre(len(toks)),
			strings.Join(reached, ", "))
		if anyIdle {
			msg += " An interface marked `no DHCP configured` runs neither a DHCP " +
				"server/relay nor the firewall's own DHCP client, so the zone-level " +
				"token opens udp/67-68 there for nothing — removing it narrows nothing " +
				"in use."
		}
		if anyClient {
			msg += " An interface marked `DHCP client` runs the firewall's OWN client, " +
				"which needs udp/68 for its unicast renewals. The vendor rule quoted " +
				"above is about a DHCP SERVER knowing its incoming interface and does " +
				"not speak to the client, so on that interface the token is holding up " +
				"the interface's ADDRESS, not merely a service — move it, do not drop it."
		}
		msg += " (#6519 parity deviation; xpf still enforces the zone-level " +
			"authorization today.)"
		warnings = append(warnings, msg)
	}
	return warnings
}

// pluralIsAre picks the verb for a token list of length n.
func pluralIsAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// hostInboundDHCPRoles records WHY an interface would need udp/67-68 admitted.
// The two halves are independent booleans rather than an enum because an
// interface can legitimately be both (a relay member that also runs the
// firewall's own client), and picking a winner would invent a precedence the
// config does not state.
type hostInboundDHCPRoles struct {
	server bool // dhcp-local-server / dhcpv6-local-server / dhcp-relay member
	client bool // family inet { dhcp; } — the firewall's OWN DHCP client
}

// hostInboundSameInterface reports whether two interface refs name the same
// interface for DHCP-role purposes. A bare physical ref and a unit ref under it
// are the same interface (`reth1` vs `reth1.0`) — the #3720 physical/unit
// relationship — but two DIFFERENT units are not (`reth1.0` vs `reth1.50`).
// Basing both sides on the physical would collapse those two, over-matching a
// sibling unit's DHCP role onto an interface that has none.
func hostInboundSameInterface(a, b string) bool {
	if a == b {
		return true
	}
	aBase, _, aUnit := strings.Cut(a, ".")
	bBase, _, bUnit := strings.Cut(b, ".")
	if aBase != bBase {
		return false
	}
	// Equal bases: same interface only when exactly one side is the bare
	// physical. Two distinct units are distinct interfaces.
	return aUnit != bUnit
}

// hostInboundDHCPServerRefs collects every interface ref that receives DHCP on
// the firewall's behalf as a SERVER: dhcp-local-server and dhcpv6-local-server
// group members, and dhcp-relay group members. A relay counts because it too
// receives client DISCOVER on udp/67 and is the case the vendor rationale
// describes — the incoming interface must be known to send the reply back.
func hostInboundDHCPServerRefs(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var refs []string
	for _, srv := range []*DHCPLocalServerConfig{
		cfg.System.DHCPServer.DHCPLocalServer,
		cfg.System.DHCPServer.DHCPv6LocalServer,
	} {
		if srv == nil {
			continue
		}
		for _, g := range srv.Groups {
			if g != nil {
				refs = append(refs, g.Interfaces...)
			}
		}
	}
	if cfg.ForwardingOptions.DHCPRelay != nil {
		for _, g := range cfg.ForwardingOptions.DHCPRelay.Groups {
			if g != nil {
				refs = append(refs, g.Interfaces...)
			}
		}
	}
	return refs
}

// hostInboundIsDHCPClient reports whether ref runs the firewall's OWN DHCPv4
// client (`family inet { dhcp; }`). Only v4 is consulted: the tokens this
// advisory is about (`dhcp` / `bootp`) open udp/67-68, and `dhcpv6` is
// deliberately out of the vendor sentence's scope (see the file header).
//
// A bare physical ref answers for ANY unit beneath it, because the zone
// membership names the physical while the client is configured on a unit.
func hostInboundIsDHCPClient(cfg *Config, ref string) bool {
	if cfg == nil || ref == "" {
		return false
	}
	base, unitStr, hasUnit := strings.Cut(ref, ".")
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return false
	}
	for n, u := range ifc.Units {
		if u == nil || !u.DHCP {
			continue
		}
		if !hasUnit {
			return true
		}
		if fmt.Sprintf("%d", n) == unitStr {
			return true
		}
	}
	return false
}

// hostInboundDHCPRolesFor classifies one interface ref.
func hostInboundDHCPRolesFor(cfg *Config, serverRefs []string, ref string) hostInboundDHCPRoles {
	var r hostInboundDHCPRoles
	for _, s := range serverRefs {
		if hostInboundSameInterface(s, ref) {
			r.server = true
			break
		}
	}
	r.client = hostInboundIsDHCPClient(cfg, ref)
	return r
}

// hostInboundDHCPRoleLabel is the parenthetical the advisory appends to an
// interface name, naming which DHCP role makes the zone-level token load-bearing
// there. "no DHCP configured" is the operationally most useful of the three: it
// says the token authorizes udp/67-68 for nothing.
func hostInboundDHCPRoleLabel(r hostInboundDHCPRoles) string {
	switch {
	case r.server && r.client:
		return "DHCP server and client"
	case r.server:
		return "DHCP server"
	case r.client:
		return "DHCP client"
	default:
		return "no DHCP configured"
	}
}
