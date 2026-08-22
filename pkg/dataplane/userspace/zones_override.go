package userspace

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// effectiveHostInboundTokens returns the EFFECTIVE host-inbound system-service
// and protocol token sets for an interface (#3362), lower-cased, trimmed and
// de-duplicated for map keying. Either argument may be nil.
//
// #6515: an interface that declares a `host-inbound-traffic` stanza is described
// ENTIRELY by it — the zone-level set is REPLACED, not unioned ("Interface
// configuration overrides that of the zone", Junos Security Zones). Presence of
// the stanza, not emptiness, is the discriminator: ifaceHI non-nil means the
// operator authored one, and an explicitly empty one is a deny-all override. The
// decision itself is config.EffectiveHostInboundTokens, shared with the display
// surfaces, the commit-time advisories and the duplicate-host-address gate, so
// enforcement and every description of it act on ONE object. Before #3226 this
// file owned its own combination and the advisories computed a per-RAW-STANZA
// view, so the two reasoned about DIFFERENT objects and the advice contradicted
// enforcement (a zone-level `any-service` with a per-interface `rpm` warned rpm
// was DENIED while this builder admitted it). This wrapper keeps the lower-casing
// the dataplane needs for map keying — the shared config helper preserves
// authored case for the display surfaces.
//
// Before #6515 this was a UNION (unionHostInboundTokens), so an interface stanza
// could only ever WIDEN admission relative to the zone.
func effectiveHostInboundTokens(zoneHI, ifaceHI *config.HostInboundTraffic) (svc, proto []string) {
	var zs, zp, is, ip []string
	if zoneHI != nil {
		zs, zp = zoneHI.SystemServices, zoneHI.Protocols
	}
	if ifaceHI != nil {
		is, ip = ifaceHI.SystemServices, ifaceHI.Protocols
	}
	overridden := ifaceHI != nil
	return lowerDedup(config.EffectiveHostInboundTokens(zs, is, overridden)),
		lowerDedup(config.EffectiveHostInboundTokens(zp, ip, overridden))
}

// lowerDedup lower-cases, trims and de-duplicates in one pass, preserving first
// -seen order. The shared config helper dedups on the AUTHORED token (it
// preserves case for the display surfaces), so `SSH` and `ssh` both survive it
// and would collapse to a duplicate `ssh` here. Plain lowerTokens does not
// dedup, so it would leak that duplicate into the dataplane view — harmless for
// the classifier, which is set-based, but a gratuitous change to a snapshot
// other tests compare exactly. Dedup on the LOWER-CASED token, exactly as this
// function did before it delegated.
func lowerDedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeHostInboundTraffic is the #3720 physical->unit union, now owned by
// pkg/config so the commit-time advisories resolve overrides exactly as this
// package enforces them (#6640). See config.MergeHostInboundTraffic.
func mergeHostInboundTraffic(a, b *config.HostInboundTraffic) *config.HostInboundTraffic {
	return config.MergeHostInboundTraffic(a, b)
}

// buildInterfaceHostInboundMap resolves per-interface host-inbound overrides
// (#3362) keyed by the interface ref as it appears on a resolved interface
// snapshot (InterfaceSnapshot.Name).
//
// #6640: the resolution — the #3720 physical->unit merge, the #3720 M01 /
// #5489 cross-zone quarantines and the #5878 canonicalisation — now lives in
// pkg/config as ResolveInterfaceHostInbound, so the commit-time advisory in
// compiler_validate_warn.go computes the EFFECTIVE override from the same
// function this enforcement path does instead of approximating it from the raw
// stanzas. Breaking that function must red an advisory test AND an enforcement
// test together; if only one reds they are not actually sharing it.
func buildInterfaceHostInboundMap(cfg *config.Config) map[string]*config.HostInboundTraffic {
	return config.ResolveInterfaceHostInbound(cfg)
}
