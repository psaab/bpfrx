package userspace

import (
	"fmt"
	"sort"
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

// mergeHostInboundTraffic returns a NEW *config.HostInboundTraffic whose token
// lists are the order-preserving UNION of a and b (a's tokens first, then any of
// b's not already present, exact-string dedup). It underpins the #3720
// physical→unit override resolution: a physical-interface override and a
// more-specific unit-level override on the same unit are UNIONed (both are
// INTERFACE-level statements) rather than the sorted-first physical ref silently
// shadowing the unit ref (the #3720 first-writer-wins bug). #6515 changed how the
// RESULT combines with the zone level — it replaces it — not this merge. Returns
// nil only when BOTH inputs are nil; a fresh struct is always allocated so the
// shared config-owned override objects are never mutated in place.
func mergeHostInboundTraffic(a, b *config.HostInboundTraffic) *config.HostInboundTraffic {
	if a == nil && b == nil {
		return nil
	}
	appendUnique := func(dst *[]string, src []string) {
		for _, t := range src {
			dup := false
			for _, e := range *dst {
				if e == t {
					dup = true
					break
				}
			}
			if !dup {
				*dst = append(*dst, t)
			}
		}
	}
	out := &config.HostInboundTraffic{}
	if a != nil {
		appendUnique(&out.SystemServices, a.SystemServices)
		appendUnique(&out.Protocols, a.Protocols)
	}
	if b != nil {
		appendUnique(&out.SystemServices, b.SystemServices)
		appendUnique(&out.Protocols, b.Protocols)
	}
	return out
}

// buildInterfaceHostInboundMap resolves per-interface host-inbound overrides
// (#3362) keyed by the interface ref as it appears on a resolved interface
// snapshot (InterfaceSnapshot.Name).
//
// Precedence / merge rule (#3720). A physical-interface override and a
// unit-level override are BOTH interface-level statements, so the EFFECTIVE
// override for a unit is the UNION of any physical-interface-level override that
// applies to it and its own unit-level override — never the less-specific
// physical ref shadowing the more-specific unit ref. (#6515 changed how this
// result combines with the ZONE level — it REPLACES it — and did not change this
// within-level union.):
//   - A ref naming a logical unit (contains ".") is the MOST specific override.
//     It maps ONLY itself — never a sibling unit — and is MERGED (unioned) onto
//     whatever physical-inherited set already sits on that unit key, BUT only
//     when THIS zone is the unit's authoritative owner (#5489 quarantine — a
//     unit-level override on a zone that lost ownership must not leak its tokens
//     into the winning zone's effective set on the lenient multi-owner warn
//     path). This mirrors the physical branch's #3720 cross-zone guard below.
//   - A ref naming a physical interface (no unit suffix) expands to each of its
//     configured units (mirroring buildInterfaceZoneMap), but NOT onto a unit
//     resolved to a DIFFERENT zone (#3720 M01 quarantine — a physical override
//     must not leak its tokens cross-zone on the lenient multi-owner warn path).
//     The expansion MERGES so a same-zone unit override unions rather than being
//     dropped.
//
// Before #3720 the loop wrote every key first-writer-wins in sorted ref order:
// a bare physical ref (a prefix of, and therefore sorting before, its units)
// filled out["ifN.M"] first, so the later exact unit override was skipped and
// the less-specific physical ref silently decided the unit (fail-open or
// fail-closed). Zones are still walked in sorted order and the bare physical key
// itself stays first-writer-wins across zones (deterministic), so single-level
// (physical-only or unit-only) configs are bit-identical to before.
func buildInterfaceHostInboundMap(cfg *config.Config) map[string]*config.HostInboundTraffic {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	// Resolved logical-interface → zone lookup so the physical→unit expansion can
	// skip a unit owned by a different zone (#3720 M01).
	zoneByIface := buildInterfaceZoneMap(cfg)
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
			if strings.Contains(ref, ".") {
				// #5878 phase 2: resolve the unit ref on its canonical identity so
				// a reth0.050 override lands on the same key (reth0.50) the per-unit
				// snapshot consumer looks up, and the #5489 owner guard compares the
				// canonical unit against the (now canonical) zone map.
				canonRef := config.CanonicalInterfaceUnitRef(ref)
				// #5489: a unit-level override must come ONLY from the unit's
				// authoritative zone owner. buildInterfaceZoneMap resolves the
				// owner as the first sorted zone that claims the unit; on a
				// tolerated duplicate ownership (lenient load / peer-sync retains
				// two zones both claiming the same reth0.100) this loop visits
				// BOTH zones, so without a guard the losing zone's tokens (e.g.
				// SSH) would union into out[ref] and bleed into the winning zone's
				// InterfaceSnapshot / ZoneHostInboundView. Quarantine the leak with
				// the SAME predicate the physical-expansion branch uses (#3720
				// M01): skip when a DIFFERENT zone owns this unit.
				if z := zoneByIface[canonRef]; z != "" && z != zn {
					continue
				}
				// Logical unit ref: the most specific override. Merge (union) it
				// onto any physical-inherited set already on this unit key. Because
				// refs are walked sorted and a bare physical ref sorts before its
				// units, a same-zone physical expansion below has already run, so
				// this yields physical ∪ unit.
				out[canonRef] = mergeHostInboundTraffic(out[canonRef], hib)
				continue
			}
			// Bare physical ref: first-writer-wins across zones for the bare key
			// itself (preserves the lenient cross-zone quarantine).
			if _, ok := out[ref]; !ok {
				out[ref] = hib
			}
			if ifCfg := cfg.Interfaces.Interfaces[ref]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					un := fmt.Sprintf("%s.%d", ref, unitNum)
					// #3720 M01: do not leak a physical override onto a unit that
					// resolves to a different zone.
					if z := zoneByIface[un]; z != "" && z != zn {
						continue
					}
					out[un] = mergeHostInboundTraffic(out[un], hib)
				}
			}
		}
	}
	return out
}
