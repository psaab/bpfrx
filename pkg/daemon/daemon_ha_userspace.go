package daemon

import (
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

type userspaceXSKBindingController interface {
	XSKBoundNotified() bool
	SetOnXSKBound(func())
}

// buildZoneRGMap builds a zone_id→RG mapping by looking up which interfaces
// belong to each zone, then checking those interfaces' RedundancyGroup.
// Zones with RETH interfaces inherit the RETH's RG; non-RETH zones are not
// included (they fall back to global IsPrimaryFn in session sync).
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint16) map[uint16]int {
	result := make(map[uint16]int)
	for zoneName, zone := range cfg.Security.Zones {
		// Tolerant/programmatic/HA-peer-sync configs can leave a nil
		// zone value in the map (the established nil-slot invariant the
		// dataplane SSOT defends, e.g. zones.go's `if zone == nil`).
		// Skip it here too, otherwise the zone.Interfaces deref below
		// panics the per-RG session-sync apply path.
		if zone == nil {
			continue
		}
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		rgSeen := -1
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "reth0.0" → "reth0") for config lookup.
			baseName := ifName
			if idx := strings.IndexByte(ifName, '.'); idx >= 0 {
				baseName = ifName[:idx]
			}
			// comma-ok checks key-presence, not value-non-nil; a
			// (nil, true) map entry would panic on ifc.RedundancyGroup.
			if ifc, ok := cfg.Interfaces.Interfaces[baseName]; ok && ifc != nil && ifc.RedundancyGroup > 0 {
				if rgSeen >= 0 && rgSeen != ifc.RedundancyGroup {
					slog.Warn("zone spans multiple redundancy groups; "+
						"active/active session sync ownership is ambiguous",
						"zone", zoneName,
						"rg1", rgSeen, "rg2", ifc.RedundancyGroup)
				}
				if rgSeen < 0 {
					result[zid] = ifc.RedundancyGroup
					rgSeen = ifc.RedundancyGroup
				}
			}
		}
	}
	return result
}

// rgHasRETH returns whether the given redundancy group has any RETH interfaces.
func rgHasRETH(cfg *config.Config, rgID int) bool {
	if cfg == nil {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}
