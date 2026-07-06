package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// host_inbound_classify.go is the #3627 B1a host-inbound admission CLASSIFIER:
// given a host-bound (to-zone junos-host) query tuple and the ingress zone, it
// reports WHICH host-inbound-traffic system-service / protocol token admits the
// packet — or that the box denies it, admits it globally (ICMP error/ND, ESP/AH),
// or cannot classify it. It is consumed by the operator-plane match-policies
// simulator (pkg/policymatch) so the host-inbound verdict names the admitting
// token instead of the fixed "local delivery subject to host-inbound-traffic"
// string.
//
// It is a DIAGNOSTIC, not the enforcement path: the kernel-nft chain
// (pkg/daemon/daemon_nft.go) and the Rust AF_XDP classifier
// (userspace-dp/.../forwarding/host_inbound.rs) enforce. To avoid a THIRD
// token->port truth drifting from those two, the classifier reads the SAME
// structured SSOT the nft builder renders from (config.HostInboundServiceMatch /
// config.HostInboundProtocolMatch, #3627 B1a) and mirrors the global pre-accepts
// the nft chain applies at the top of `chain input`
// (buildHostInboundFilterPayload) and the Rust is_icmp_host_inbound_global_accept
// (#3171): ESP/AH raw data plane, ICMP error/PMTUD, and the IPv6 ND set.
//
// Faithful to the enforcement paths (plan §5): a zone can carry MULTIPLE
// per-interface effective views (#3362) — the query has no ingress interface, so
// admission is reported if ANY view for the ingress zone admits the tuple.
// Post-#3405 a configured zone with no host-inbound-traffic stanza default-DENIES
// (its view carries empty token sets), so "unmatched host policy" does NOT imply
// delivery. Lifeline interfaces (fxp0/em0/fab*) are excluded from the views and
// so are never classified here (their host traffic is served unconditionally).

// HostInboundStatus classifies how the ingress zone's host-inbound-traffic
// admission gate treats a host-bound query tuple (#3627 B1a). It is presence-safe
// so the four states are distinguishable — a bare token string could not tell
// "denied" from "not computed" from "admitted by a global accept".
type HostInboundStatus int

const (
	// HostInboundNotComputed is the zero value: the admission was not computed
	// (not a host-bound query, or no config). Rendered as absence.
	HostInboundNotComputed HostInboundStatus = iota
	// HostInboundIndeterminate: the query omits the protocol, or omits the
	// destination-port / icmp-type a port/ICMP token needs, so the admitting
	// token cannot be identified. Never reported as a false admit.
	HostInboundIndeterminate
	// HostInboundGlobalAccept: admitted by a GLOBAL pre-accept independent of the
	// zone's host-inbound-traffic set (ICMP error/PMTUD, IPv6 ND, or the raw
	// ESP/AH data plane), matching the top-of-chain nft accepts (#3171).
	HostInboundGlobalAccept
	// HostInboundTokenAdmit: admitted by a named host-inbound-traffic token
	// (Token/Kind identify it).
	HostInboundTokenAdmit
	// HostInboundDenied: the ingress zone's host-inbound-traffic admits nothing
	// matching this tuple — the box drops the packet (Junos default-deny).
	HostInboundDenied
)

func (s HostInboundStatus) String() string {
	switch s {
	case HostInboundIndeterminate:
		return "indeterminate"
	case HostInboundGlobalAccept:
		return "global-accept"
	case HostInboundTokenAdmit:
		return "token-admit"
	case HostInboundDenied:
		return "denied"
	default:
		return "not-computed"
	}
}

// HostInboundAdmission is the classifier verdict for a host-bound query tuple
// (#3627 B1a). Token/Kind are meaningful only when Status == HostInboundTokenAdmit.
type HostInboundAdmission struct {
	Status HostInboundStatus
	// Token is the admitting host-inbound-traffic token (e.g. "ssh", "bgp",
	// "all"); set only for HostInboundTokenAdmit.
	Token string
	// Kind is the stanza the token belongs to: "system-services" or "protocols".
	// Set only for HostInboundTokenAdmit.
	Kind string
}

// Describe renders the operator-facing one-line explanation of the admission,
// appended to the host-inbound match-policies verdict. Empty for
// HostInboundNotComputed (nothing to say).
func (a HostInboundAdmission) Describe() string {
	switch a.Status {
	case HostInboundTokenAdmit:
		if a.Token == "all" || a.Token == "any-service" {
			return fmt.Sprintf("admitted by host-inbound-traffic system-services %s (all host services open)", a.Token)
		}
		return fmt.Sprintf("admitted by host-inbound-traffic %s %s", a.Kind, a.Token)
	case HostInboundGlobalAccept:
		return "admitted by a global accept (ICMP error/PMTUD, IPv6 ND, or ESP/AH) independent of this zone's host-inbound-traffic set"
	case HostInboundDenied:
		return "DENIED by host-inbound-traffic — no system-service/protocol admits this tuple, so the box drops it"
	case HostInboundIndeterminate:
		return "indeterminate — specify protocol (and destination-port or icmp-type) to identify the admitting host-inbound-traffic token"
	default:
		return ""
	}
}

// ClassifyHostInbound reports how the ingress zone's host-inbound-traffic gate
// treats a host-bound query tuple (#3627 B1a). proto/hasProto carry the resolved
// IP protocol number (hasProto false = the query omitted the protocol); dstPort
// is the destination port (<= 0 = unspecified); icmpType is the ICMP/ICMPv6 type
// (nil = unspecified); family is "ip" / "ip6" from the query's destination
// address, or "" when the query gives no IP (both families are then tried and
// admission is reported if either admits).
func ClassifyHostInbound(cfg *config.Config, fromZone string, proto uint8, hasProto bool, dstPort int, icmpType *uint8, family string) HostInboundAdmission {
	if cfg == nil || fromZone == "" {
		return HostInboundAdmission{Status: HostInboundNotComputed}
	}

	views := viewsForZone(cfg, fromZone)

	// Full-admit (`system-services all` / `any-service`) admits everything,
	// independent of the tuple — report it even when the tuple is otherwise
	// indeterminate.
	for _, v := range views {
		for _, s := range v.SystemServices {
			if config.HostInboundFullAdmitService(s) {
				return HostInboundAdmission{Status: HostInboundTokenAdmit, Token: s, Kind: "system-services"}
			}
		}
	}

	// Global pre-accepts (ICMP error/PMTUD, IPv6 ND, ESP/AH), mirroring the
	// top-of-chain nft accepts (#3171). Needs the protocol.
	if hasProto && hostInboundGlobalAccept(proto, icmpType) {
		return HostInboundAdmission{Status: HostInboundGlobalAccept}
	}

	if !hasProto {
		return HostInboundAdmission{Status: HostInboundIndeterminate}
	}
	// A port/ICMP token cannot be identified without the port / icmp-type.
	if (proto == config.HostInboundProtoTCP || proto == config.HostInboundProtoUDP) && dstPort <= 0 {
		return HostInboundAdmission{Status: HostInboundIndeterminate}
	}
	if (proto == config.HostInboundProtoICMP || proto == config.HostInboundProtoICMPv6) && icmpType == nil {
		return HostInboundAdmission{Status: HostInboundIndeterminate}
	}

	fams := []string{family}
	if family == "" {
		fams = []string{"ip", "ip6"}
	}
	for _, v := range views {
		for _, fam := range fams {
			if tok, kind, ok := hostInboundViewAdmit(v, proto, dstPort, icmpType, fam); ok {
				return HostInboundAdmission{Status: HostInboundTokenAdmit, Token: tok, Kind: kind}
			}
		}
	}
	// The zone is configured (post-#3405 every configured zone enforces) and
	// nothing admits — default-deny.
	return HostInboundAdmission{Status: HostInboundDenied}
}

// viewsForZone returns the host-inbound effective views for the given ingress
// zone (there may be several, #3362).
func viewsForZone(cfg *config.Config, zone string) []ZoneHostInboundView {
	var out []ZoneHostInboundView
	for _, v := range BuildZoneHostInboundViews(cfg) {
		if v.Zone == zone {
			out = append(out, v)
		}
	}
	return out
}

// hostInboundViewAdmit reports the first token in the view that admits the tuple
// (system-services before protocols), skipping the non-admitting ident-reset
// (Reject). Family-scoped via the SSOT.
func hostInboundViewAdmit(v ZoneHostInboundView, proto uint8, dstPort int, icmpType *uint8, family string) (token, kind string, admitted bool) {
	for _, s := range v.SystemServices {
		for _, m := range config.HostInboundServiceMatch(s, family) {
			if !m.Reject && l4MatchAdmits(m, proto, dstPort, icmpType) {
				return s, "system-services", true
			}
		}
	}
	for _, p := range v.Protocols {
		for _, m := range config.HostInboundProtocolMatch(p, family) {
			if l4MatchAdmits(m, proto, dstPort, icmpType) {
				return p, "protocols", true
			}
		}
	}
	return "", "", false
}

// l4MatchAdmits reports whether a structured host-inbound match admits the query
// tuple (proto, dstPort, icmpType). It mirrors the Rust ZoneHostInbound::admits
// per-tuple semantics against the SSOT L4Match shape.
func l4MatchAdmits(m config.L4Match, proto uint8, dstPort int, icmpType *uint8) bool {
	if m.Proto != proto {
		return false
	}
	switch m.Proto {
	case config.HostInboundProtoTCP, config.HostInboundProtoUDP:
		if len(m.Ports) == 0 {
			return true
		}
		if dstPort <= 0 || dstPort > 65535 {
			return false
		}
		dp := uint16(dstPort)
		for _, pr := range m.Ports {
			if dp >= pr.Lo && dp <= pr.Hi {
				return true
			}
		}
		return false
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		if m.ICMPType == nil {
			return true
		}
		if icmpType == nil {
			return false
		}
		return *icmpType == *m.ICMPType
	default:
		// Bare IP protocol (gre/ospf/pim/...): the protocol match is sufficient.
		return true
	}
}

// hostInboundGlobalAccept mirrors the top-of-chain nft global accepts
// (buildHostInboundFilterPayload) and the Rust is_icmp_host_inbound_global_accept
// (#3171): the raw ESP (50) / AH (51) data plane, and the ICMP error/PMTUD +
// IPv6 ND subtypes, are admitted regardless of the zone's host-inbound-traffic
// set. Echo-request (v4 8 / v6 128) and IPv4 router-advert/solicit (9/10) are
// NOT global — they stay gated on the `ping` / `router-discovery` tokens.
func hostInboundGlobalAccept(proto uint8, icmpType *uint8) bool {
	// Raw ESP / AH data plane (nft `meta l4proto { 50, 51 } accept`).
	if proto == 50 || proto == 51 {
		return true
	}
	if icmpType == nil {
		return false
	}
	t := *icmpType
	switch proto {
	case config.HostInboundProtoICMP: // ICMPv4 errors: dest-unreach(3), time-exceeded(11), param-problem(12)
		return t == 3 || t == 11 || t == 12
	case config.HostInboundProtoICMPv6: // ICMPv6 errors 1-4 + ND 133-137
		switch t {
		case 1, 2, 3, 4, 133, 134, 135, 136, 137:
			return true
		}
	}
	return false
}
