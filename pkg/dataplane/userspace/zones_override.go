package userspace

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

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

// mergeHostInboundTraffic returns a NEW *config.HostInboundTraffic whose token
// lists are the order-preserving UNION of a and b (a's tokens first, then any of
// b's not already present, exact-string dedup). It underpins the #3720 additive
// physical→unit override resolution: a physical-interface override and a
// more-specific unit-level override on the same unit are UNIONed (Junos
// host-inbound is additive across levels) rather than the sorted-first physical
// ref silently shadowing the unit ref (the #3720 first-writer-wins bug). Returns
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
// Precedence / merge rule (#3720). Junos host-inbound is ADDITIVE across the
// override levels, so the EFFECTIVE override for a unit is the UNION of any
// physical-interface-level override that applies to it and its own unit-level
// override — never the less-specific physical ref shadowing the more-specific
// unit ref:
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
