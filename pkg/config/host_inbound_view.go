package config

import "strings"

// host_inbound_view.go is the shared presentation SSOT for a security zone's
// host-inbound-traffic admission posture (#3654 L02). Before #3654 every text /
// CLI surface (local `show security zones` / `show interfaces` / `test
// security-zone interface`, gRPC text zones + interface diagnostic, and the
// remote `cmd/cli` zone view) re-implemented the same ad-hoc "print the
// zone-level HostInboundTraffic set" block and every one of them dropped the
// per-interface override (#3362) and the no-stanza default-deny posture
// (#3405). Routing all six through this one presenter keeps them from drifting
// again and mirrors the structured REST/gRPC contract (#3328/#3405/#3653):
// every configured zone is host-inbound ENFORCING, and the EFFECTIVE admission
// set for an interface is the UNION of the zone-level set and its interface
// override (Junos additive semantics).

// UnionHostInboundTokens returns the effective host-inbound token set for the
// combination of a zone-level list and a per-interface override list: the
// zone-level tokens first in their authored order, then any override-only
// tokens, with empties skipped and exact-duplicate tokens collapsed. This is
// the display-side peer of the dataplane's unionHostInboundTokens
// (dataplane/userspace/zones.go); it preserves the authored token case so the
// text surfaces show tokens exactly as the structured API does (the dataplane
// path lower-cases for map keying, a concern that does not apply to display).
func UnionHostInboundTokens(zone, iface []string) []string {
	seen := make(map[string]bool, len(zone)+len(iface))
	out := make([]string, 0, len(zone)+len(iface))
	add := func(src []string) {
		for _, t := range src {
			t = strings.TrimSpace(t)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	add(zone)
	add(iface)
	return out
}

// HostInboundDenyReason returns the parenthetical explaining WHY a zone or
// interface admits no host-inbound traffic, for the default-deny posture line
// (#3654 M03). overridden marks that the interface declares its own
// host-inbound-traffic stanza; zoneConfigured marks that a zone-level stanza is
// present. All three cases default-DENY host-bound traffic post-#3405; the
// wording only tells the operator which stanza produced the empty set.
func HostInboundDenyReason(overridden, zoneConfigured bool) string {
	switch {
	case overridden:
		return "interface override: deny-all"
	case zoneConfigured:
		return "empty stanza"
	default:
		return "no stanza"
	}
}

// InterfaceHostInboundEffective returns the EFFECTIVE host-inbound admission set
// for a single interface ref in the zone: the UNION of the zone-level set and
// the per-interface override for ref (if any). overridden reports whether ref
// declares its own host-inbound-traffic stanza (#3362). Used by the
// interface-scoped surfaces (`show interfaces`, `test security-zone interface`,
// gRPC interface diagnostic) which must show the effective set for ONE
// interface rather than iterate the whole zone.
func (z *ZoneConfig) InterfaceHostInboundEffective(ref string) (svc, proto []string, overridden bool) {
	var zoneSvc, zoneProto []string
	if z != nil && z.HostInboundTraffic != nil {
		zoneSvc = z.HostInboundTraffic.SystemServices
		zoneProto = z.HostInboundTraffic.Protocols
	}
	var ov *HostInboundTraffic
	if z != nil {
		ov = z.InterfaceHostInbound[ref]
	}
	if ov == nil {
		return UnionHostInboundTokens(zoneSvc, nil), UnionHostInboundTokens(zoneProto, nil), false
	}
	return UnionHostInboundTokens(zoneSvc, ov.SystemServices),
		UnionHostInboundTokens(zoneProto, ov.Protocols), true
}

// InterfaceHostInboundView is a single per-interface host-inbound override
// (#3362) projected for display: the interface-local override tokens plus the
// EFFECTIVE (zone-level UNION override) admitted set that actually reaches the
// host on that interface.
type InterfaceHostInboundView struct {
	Interface               string
	SystemServices          []string
	Protocols               []string
	EffectiveSystemServices []string
	EffectiveProtocols      []string
}

// HostInboundView is the zone-scoped presentation view shared by the
// zone-listing surfaces (`show security zones`, gRPC text zones, remote
// cmd/cli). ZoneConfigured records whether a zone-level host-inbound-traffic
// stanza is present (populated or explicit-empty); the zone-level admitted set
// is in ZoneSystemServices / ZoneProtocols; Interfaces holds the per-interface
// overrides in sorted order.
type HostInboundView struct {
	ZoneConfigured     bool
	ZoneSystemServices []string
	ZoneProtocols      []string
	Interfaces         []InterfaceHostInboundView
}

// HostInboundView builds the presentation view for a zone from its typed
// config. Nil-safe (returns a zero view for a nil zone).
func (z *ZoneConfig) HostInboundView() HostInboundView {
	v := HostInboundView{}
	if z == nil {
		return v
	}
	if z.HostInboundTraffic != nil {
		v.ZoneConfigured = true
		v.ZoneSystemServices = append([]string(nil), z.HostInboundTraffic.SystemServices...)
		v.ZoneProtocols = append([]string(nil), z.HostInboundTraffic.Protocols...)
	}
	for _, ref := range z.SortedInterfaceHostInboundRefs() {
		ov := z.InterfaceHostInbound[ref]
		if ov == nil {
			continue
		}
		v.Interfaces = append(v.Interfaces, InterfaceHostInboundView{
			Interface:               ref,
			SystemServices:          append([]string(nil), ov.SystemServices...),
			Protocols:               append([]string(nil), ov.Protocols...),
			EffectiveSystemServices: UnionHostInboundTokens(v.ZoneSystemServices, ov.SystemServices),
			EffectiveProtocols:      UnionHostInboundTokens(v.ZoneProtocols, ov.Protocols),
		})
	}
	return v
}

// RenderInterfaceHostInbound returns the host-inbound presentation block for
// ONE interface ref in the zone (#3654 H06/H08 — the per-interface admission
// diagnostic), one line per slice element with NO trailing newline. It shows
// the zone-level admitted set and, when ref declares its own
// host-inbound-traffic override, both a marker and the EFFECTIVE (zone UNION
// interface) admitted set for that interface. A default-deny posture line is
// emitted when the effective set is empty, so a blank section cannot be misread
// as "not enforced".
func (z *ZoneConfig) RenderInterfaceHostInbound(ref string, l HostInboundLabels) []string {
	var zoneSvc, zoneProto []string
	zoneConfigured := false
	if z != nil && z.HostInboundTraffic != nil {
		zoneConfigured = true
		zoneSvc = z.HostInboundTraffic.SystemServices
		zoneProto = z.HostInboundTraffic.Protocols
	}
	effSvc, effProto, overridden := z.InterfaceHostInboundEffective(ref)

	join := func(toks []string) string {
		if len(toks) == 0 {
			return "(none)"
		}
		return strings.Join(toks, l.Sep)
	}
	var lines []string
	if len(zoneSvc) > 0 {
		lines = append(lines, l.Indent+l.ServicesLabel+": "+strings.Join(zoneSvc, l.Sep))
	}
	if len(zoneProto) > 0 {
		lines = append(lines, l.Indent+l.ProtocolsLabel+": "+strings.Join(zoneProto, l.Sep))
	}
	if overridden {
		lines = append(lines,
			l.Indent+"Host-inbound interface override on "+ref+":",
			l.Indent+"  effective "+strings.ToLower(l.ServicesLabel)+": "+join(effSvc),
			l.Indent+"  effective "+strings.ToLower(l.ProtocolsLabel)+": "+join(effProto),
		)
	}
	if len(effSvc) == 0 && len(effProto) == 0 {
		lines = append(lines, l.Indent+"Host-inbound: default deny ("+
			HostInboundDenyReason(overridden, zoneConfigured)+")")
	}
	return lines
}

// HostInboundLabels lets each zone-listing surface keep its established
// zone-level line labels and token separator while sharing the presentation
// logic for the per-interface override block and the default-deny posture line.
type HostInboundLabels struct {
	Indent         string // leading indent for each rendered line
	Sep            string // token-list separator (" " or ", ")
	ServicesLabel  string // zone-level system-services label
	ProtocolsLabel string // zone-level protocols label
}

// Render returns the host-inbound presentation block for a zone (#3654), one
// line per slice element with NO trailing newline. It emits, in order: the
// zone-level system-services / protocols lines (when non-empty), an explicit
// default-deny posture line when the zone admits nothing at the zone level
// (M03 — so a blank host-inbound section can never be misread as "not
// enforced"), and one block per per-interface override showing the
// interface-local tokens plus the effective (zone UNION interface) admitted set
// (H04/H07/H09).
//
// The zone-level default-deny posture line is emitted regardless of whether any
// per-interface override exists (#3671 / H08): the zone posture still governs
// every NON-overridden interface in the zone, so a partial interface override
// must not erase the visible default posture for the rest of the zone. The
// override blocks are ADDITIONAL context printed below the zone posture, never a
// replacement for it.
func (v HostInboundView) Render(l HostInboundLabels) []string {
	join := func(toks []string) string {
		if len(toks) == 0 {
			return "(none)"
		}
		return strings.Join(toks, l.Sep)
	}
	var lines []string
	if len(v.ZoneSystemServices) > 0 {
		lines = append(lines, l.Indent+l.ServicesLabel+": "+strings.Join(v.ZoneSystemServices, l.Sep))
	}
	if len(v.ZoneProtocols) > 0 {
		lines = append(lines, l.Indent+l.ProtocolsLabel+": "+strings.Join(v.ZoneProtocols, l.Sep))
	}
	// The zone-level default-deny posture line is emitted whenever the zone
	// admits nothing at the zone level, REGARDLESS of whether per-interface
	// overrides exist (#3671 / H08). The zone posture governs every
	// non-overridden interface, so a partial interface override must not
	// suppress the visible zone posture; the override blocks below are
	// additional context, not a replacement.
	if len(v.ZoneSystemServices) == 0 && len(v.ZoneProtocols) == 0 {
		lines = append(lines, l.Indent+"Host-inbound: default deny ("+
			HostInboundDenyReason(false, v.ZoneConfigured)+")")
	}
	if len(v.Interfaces) > 0 {
		lines = append(lines, l.Indent+"Host-inbound interface overrides:")
		for _, iface := range v.Interfaces {
			lines = append(lines,
				l.Indent+"  "+iface.Interface+":",
				l.Indent+"    override system-services: "+join(iface.SystemServices),
				l.Indent+"    override protocols: "+join(iface.Protocols),
				l.Indent+"    effective system-services: "+join(iface.EffectiveSystemServices),
				l.Indent+"    effective protocols: "+join(iface.EffectiveProtocols),
			)
		}
	}
	return lines
}
