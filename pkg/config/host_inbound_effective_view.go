package config

import (
	"fmt"
	"sort"
	"strings"
)

// The EFFECTIVE host-inbound view, shared by the dataplane enforcement builders
// and the commit-time advisories (#6640).
//
// These three functions used to live in pkg/dataplane/userspace, which imports
// this package — so the commit-time advisory in compiler_validate_warn.go could
// not call them and re-derived its own approximation of enforcement instead:
// a union of the zone stanza with each RAW interface stanza, with no
// physical->unit resolution at all. The two therefore reasoned about DIFFERENT
// OBJECTS, and every divergence found so far (#3226, #6616, #6640) has been a
// place where enforcement grew a rule the advisory did not copy. Three rounds of
// copying one more rule is the signal that copying is the wrong shape: the view
// moves HERE, the enforcement builders delegate, and the advisory calls the same
// function. A change to the resolution rule now moves both at once or neither.
//
// Nothing about the resolution changed in the move. The userspace names
// (buildInterfaceZoneMap / buildInterfaceHostInboundMap / mergeHostInboundTraffic)
// remain as one-line delegations so their call sites and the doc trail are
// unchanged.

func InterfaceZoneMap(cfg *Config) map[string]string {
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
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			// #5878 phase 2: bind the zone reference on its CANONICAL logical-unit
			// identity so ge-0/0/0.01 and ge-0/0/0.1 resolve to the same runtime
			// unit as the interface's `unit 1` definition. The per-unit snapshot
			// consumer (buildInterfaceSnapshots) keys this map by the canonical
			// "%s.%d" unit name, so a raw ".01" key would miss and the unit would
			// bind to NO zone. A bare ref or a malformed suffix is unchanged.
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

// MergeHostInboundTraffic returns a NEW *HostInboundTraffic whose token
// lists are the order-preserving UNION of a and b (a's tokens first, then any of
// b's not already present, exact-string dedup). It underpins the #3720
// physical→unit override resolution: a physical-interface override and a
// more-specific unit-level override on the same unit are UNIONed (both are
// INTERFACE-level statements) rather than the sorted-first physical ref silently
// shadowing the unit ref (the #3720 first-writer-wins bug). #6515 changed how the
// RESULT combines with the zone level — it replaces it — not this merge. Returns
// nil only when BOTH inputs are nil; a fresh struct is always allocated so the
// shared config-owned override objects are never mutated in place.
func MergeHostInboundTraffic(a, b *HostInboundTraffic) *HostInboundTraffic {
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
	out := &HostInboundTraffic{}
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

// ResolveInterfaceHostInbound resolves per-interface host-inbound overrides
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
//     configured units (mirroring InterfaceZoneMap), but NOT onto a unit
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
func ResolveInterfaceHostInbound(cfg *Config) map[string]*HostInboundTraffic {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	// Resolved logical-interface → zone lookup so the physical→unit expansion can
	// skip a unit owned by a different zone (#3720 M01).
	zoneByIface := InterfaceZoneMap(cfg)
	out := make(map[string]*HostInboundTraffic)
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
				canonRef := CanonicalInterfaceUnitRef(ref)
				// #5489: a unit-level override must come ONLY from the unit's
				// authoritative zone owner. InterfaceZoneMap resolves the
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
				out[canonRef] = MergeHostInboundTraffic(out[canonRef], hib)
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
					out[un] = MergeHostInboundTraffic(out[un], hib)
				}
			}
		}
	}
	return out
}
