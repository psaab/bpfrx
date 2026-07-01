package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSyslogZoneNameMapUsesStableZoneID is the RED-on-revert guard for the #3704
// follow-up: reloadSyslog (local-console commit/rollback path) builds the syslog
// zone-id -> name reverse map keyed by the STABLE name-hash
// config.StableZoneID(name), NOT by a sorted-positional (i+1) index.
//
// The event reader is SHARED with the daemon, whose applySyslogConfig /
// buildZoneIDs publishes the name-hash map; reloadSyslog runs AFTER that on
// every local-TTY commit. A positional map would clobber the shared reader with
// wrong ids and regress RT_FLOW zone rendering to `zone-N`. Reverting
// syslogZoneNameMap to `znMap[uint16(i+1)] = name` turns this RED: the
// StableZoneID key would resolve to the wrong name (or be absent) and the
// positional keys 1..N would be populated instead.
func TestSyslogZoneNameMapUsesStableZoneID(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
		"dmz":     {Name: "dmz"},
	}

	got := syslogZoneNameMap(cfg)

	if len(got) != len(cfg.Security.Zones) {
		t.Fatalf("map has %d entries, want %d (a StableZoneID collision or a dropped zone): %v",
			len(got), len(cfg.Security.Zones), got)
	}

	// Exact-key assertion: each zone must resolve at its StableZoneID slot. Under
	// the reverted positional (i+1) keying, StableZoneID(name) — a name-hash in
	// [1, 65533] — almost never equals a small positional index, so got[id] would
	// be "" and this fails, proving RED-on-revert.
	for name := range cfg.Security.Zones {
		id := config.StableZoneID(name)
		if got[id] != name {
			t.Fatalf("zone %q: map[StableZoneID=%d]=%q, want %q — the reverse map is NOT keyed by StableZoneID (positional-index regression, #3704)",
				name, id, got[id], name)
		}
	}
}
