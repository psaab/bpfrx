package config

import "testing"

// #3494: ValidateConfig's warning pass dereferences zone-pair sets
// (cfg.Security.Policies), rules (zpp.Policies / cfg.Security.GlobalPolicies),
// and zone map values (cfg.Security.Zones) without nil guards. The tolerant /
// HA-sync config path (#3474/#3476 premise) can deliver nil slots that the
// enforcement/runtime walker (pkg/dataplane/userspace/{policies,zones}.go)
// already tolerates — and operators rely on these warnings to diagnose exactly
// those partially-synchronized configs. This test injects a nil zone-pair set,
// a nil rule (in a real set and in GlobalPolicies), and a nil zone value, then
// runs the warning pass. Reverting any of the compiler_validate_warn.go
// `if zpp == nil` / `if p == nil` / `if zone == nil` guards makes it panic
// (RED on revert). The strict compiler never emits these nils.
func TestValidateConfigNilSlotsNoPanic(t *testing.T) {
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"trust": {
			Name:          "trust",
			ScreenProfile: "sp", // undefined -> warning, exercises line 186 deref
			Interfaces:    []string{"ge-0/0/0.0"},
		},
		"zz-nil-zone": nil, // #3494: nil zone value (lines 186, 279)
	}
	cfg.Security.Policies = []*ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "untrust", // undefined -> warning
			Policies: []*Policy{
				{Name: "p1", SchedulerName: "sched-x"}, // undefined sched -> warning
				nil,                                    // #3494: nil rule (lines 134, 295)
			},
		},
		nil, // #3494: nil zone-pair set (lines 125, 294)
	}
	cfg.Security.GlobalPolicies = []*Policy{
		{Name: "g1", SchedulerName: "sched-y"},
		nil, // #3494: nil global rule (line 304)
	}

	// Must not panic. We don't assert on exact warning text — only that the
	// pass completes and still emits the warnings for the non-nil slots.
	warnings := ValidateConfig(cfg)
	if len(warnings) == 0 {
		t.Fatalf("expected warnings for the undefined zone/screen/scheduler refs, got none")
	}
}
