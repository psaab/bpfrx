package config

import (
	"fmt"
	"sort"
	"strings"
)

// #7509 — commit-time advisory for a parent interface whose UNITS span
// different security zones.
//
// WHY THIS EXISTS AS WELL AS THE DATAPLANE CHANGE. The dataplane now leaves a
// contested parent ifindex UNZONED rather than adjudicating a packet against
// whichever sibling unit was walked first (`forwarding_build/interfaces.rs`).
// That makes the failure SAFE — traffic falls to the default policy instead of
// being policed under a zone the operator never wrote for it. It does not make
// it LEGIBLE: an operator whose untagged trunk traffic starts being denied has
// no way to reach "these units share a base netdev and disagree about their
// zone" without reading source. That is the #8296 shape, where a config
// committed clean, rendered back verbatim, and reached no consumer while
// traffic died with nothing in the logs.
//
// The dataplane also only knows an IFINDEX. It cannot name `ge-0/0/0.100`, and
// "contested ifindex 42" is not something an operator can act on. The config
// compiler has the names, and it has them BEFORE the config is deployed — so
// the operator learns at commit rather than after traffic changes behaviour.
//
// SCOPE, wider than #7509's own framing. The issue describes interface-level
// TUNNEL units sharing one netdev. The condition is any parent whose units span
// different zones, which includes an ordinary VLAN trunk. Only traffic that
// resolves to the RAW PARENT is affected — a tagged frame resolves to its own
// logical unit ifindex first (#3021) — so in practice this is untagged traffic
// on a mixed-zone trunk.
//
// WHAT WOULD INVALIDATE IT (#4308): `native-vlan-id` is accepted-only and not
// enforced today, so untagged frames have no defined unit. If #4308 is ever
// implemented they acquire one, and this advisory becomes wrong for the native
// VLAN specifically while staying right for every other contested case.

// contestedTrunkZones returns, per base interface, the sorted distinct zones its
// UNITS are bound to — only for bases whose units span MORE THAN ONE zone.
//
// Keyed off `InterfaceZoneMap` rather than walking zones directly so this and
// the snapshot builder answer from the same source. That map already canonicalises
// unit refs (#5878), so `ge-0/0/0.01` and `ge-0/0/0.1` are one unit here, not two
// units that appear to disagree.
func contestedTrunkZones(cfg *Config) map[string][]string {
	zoneByIface := InterfaceZoneMap(cfg)
	if len(zoneByIface) == 0 {
		return nil
	}
	// base -> set of zones its units name. UNIT keys only: the base's own entry
	// in InterfaceZoneMap is the inherited fan-UP value (first unit wins), which
	// is the very guess this change removes — counting it would let a base
	// "agree" with whichever unit happened to be first.
	byBase := map[string]map[string]struct{}{}
	for iface, zone := range zoneByIface {
		base, _, ok := strings.Cut(iface, ".")
		if !ok || base == "" || zone == "" {
			continue
		}
		if byBase[base] == nil {
			byBase[base] = map[string]struct{}{}
		}
		byBase[base][zone] = struct{}{}
	}
	var out map[string][]string
	for base, zones := range byBase {
		if len(zones) < 2 {
			continue
		}
		names := make([]string, 0, len(zones))
		for z := range zones {
			names = append(names, z)
		}
		sort.Strings(names)
		if out == nil {
			out = map[string][]string{}
		}
		out[base] = names
	}
	return out
}

// appendContestedTrunkZoneAdvisoryLocked adds one advisory per contested base.
//
// A WARNING, never an error. A mixed-zone trunk is a legitimate configuration —
// its TAGGED traffic is adjudicated per unit and is unaffected — so rejecting it
// would outlaw a working config to describe a narrow consequence. We are
// declining to guess for one traffic class, not forbidding the shape.
//
// `opts.suppressContestedTrunkZoneAdvisory` silences it on the TOLERANT paths,
// which back `Store.Load` (persisted-config boot) and `Store.SyncApply` (HA peer
// sync). Without that it would fire on every boot and every peer sync of a
// config committed long ago, and an advisory an operator sees on every boot for
// a decision already made is one they learn to skip.
func appendContestedTrunkZoneAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressContestedTrunkZoneAdvisory {
		return
	}
	contested := contestedTrunkZones(cfg)
	if len(contested) == 0 {
		return
	}
	bases := make([]string, 0, len(contested))
	for base := range contested {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has units in more than one security zone (%s): UNTAGGED "+
				"traffic arriving on %s cannot be attributed to a unit, so it is left "+
				"UNZONED and falls to the default policy in both directions (#7509). "+
				"Tagged traffic on each unit is unaffected. Give the units distinct "+
				"devices, or put them in one zone, if untagged traffic on %s must be "+
				"forwarded.",
			base, strings.Join(contested[base], ", "), base, base))
	}
}
