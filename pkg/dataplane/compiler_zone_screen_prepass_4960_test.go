package dataplane

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4960 / #6894 r5: a stale zone -> screen-profile reference used to escape the
// validate-before-mutate pre-pass and abort compileZones MID-LOOP.
//
// programZoneMaps ranges cfg.Security.Zones — a Go MAP. For each zone it calls
// buildZoneConfig (which resolves the screen reference) and then SetZoneConfig,
// and only after that iterates the zone's interfaces into mapZoneInterface,
// where the real netlink / procfs writes live. So when the unknown reference is
// on a zone the runtime happens to visit SECOND or later, every earlier zone has
// already been programmed by the time the compile aborts — the half-reconfigured
// host #4960 exists to prevent, produced by the mechanism it claims to close.
//
// WHY THIS TEST RUNS THE COMPILE MANY TIMES. Map iteration order is randomised
// per range, so a single run is a coin flip: with the fix reverted, the bad zone
// is visited first roughly 1/N of the time and the compile then aborts before
// any mutation, which looks exactly like a pass. One iteration would therefore
// be a FLAKY revert probe that reports green on broken code most-but-not-all of
// the time. With N zones and k trials the probability of a reverted build
// slipping through is N^-k; at N=8 and k=24 that is ~10^-21. The randomisation
// is not noise to be suppressed here — it is half the finding, because it means
// the defect's blast radius differs run to run on the same config.

// zoneScreenPrePassConfig builds a config with EIGHT valid, interface-carrying
// zones and ONE whose screen-profile reference does not resolve.
//
// The valid zones carry interfaces on purpose. Absent the fix, reaching any one
// of them means SetZoneConfig has been called and mapZoneInterface is next — so
// the mutation the probe records is the real one, not an artefact of an
// interface-free fixture that could only ever observe the call being reached.
// The interface NAMES are deliberately non-resolvable on any host (xpfz4960*),
// which is what keeps mapZoneInterface's destructive netlink out of reach in a
// unit test; recordingDP's tripwire halts the compile at the first
// SetZoneConfig for the same reason (see recordingDP's own doc comment).
func zoneScreenPrePassConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"sp-good-4960": {Name: "sp-good-4960"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for i := 0; i < 8; i++ {
		zn := fmt.Sprintf("zone-ok-%d", i)
		ifn := fmt.Sprintf("xpfz4960%c", 'a'+i)
		cfg.Security.Zones[zn] = &config.ZoneConfig{
			Name:          zn,
			ScreenProfile: "sp-good-4960",
			Interfaces:    []string{ifn + ".0"},
		}
		cfg.Interfaces.Interfaces[ifn] = &config.InterfaceConfig{
			Name: ifn,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{fmt.Sprintf("198.51.100.%d/24", i+1)}},
			},
		}
	}
	// The offender. It names a profile the (valid, non-empty) screen set lacks.
	cfg.Security.Zones["zone-bad-screen"] = &config.ZoneConfig{
		Name:          "zone-bad-screen",
		ScreenProfile: "no-such-screen-4960",
	}
	return cfg
}

// TestStaleZoneScreenRefRejectedBeforeAnyZoneIsProgrammed_4960 is the
// fail-on-revert guard for the blocker.
//
// RED-on-revert: delete the validateZoneScreenReferences call at the top of
// compileZones AND its "zone screen references" pre-pass row, and this fails
// with "programmed N zone(s) before rejecting" on the large majority of the 24
// trials.
func TestStaleZoneScreenRefRejectedBeforeAnyZoneIsProgrammed_4960(t *testing.T) {
	const trials = 24

	for i := 0; i < trials; i++ {
		dp := &recordingDP{}

		_, err := CompileConfig(dp, zoneScreenPrePassConfig(), false)
		if err == nil {
			t.Fatalf("trial %d: an unknown screen-profile reference COMPILED — the "+
				"fixture no longer exercises the rejection at all", i)
		}
		// Asserted before the error identity: on a revert the compile aborts
		// inside compileZones with a differently-worded error, and checking the
		// wording first would bury the finding that actually matters.
		if dp.zoneConfigCalls != 0 {
			t.Fatalf("trial %d: compileZones programmed %d zone(s) before rejecting the "+
				"stale screen reference. Every one of those went through SetZoneConfig "+
				"and was one step from mapZoneInterface's netlink and /proc/sys writes, "+
				"so the host is left half-reconfigured by exactly the mechanism #4960 "+
				"exists to close. Validate every zone's screen reference BEFORE the "+
				"first zone is programmed (#6894 r5)", i, dp.zoneConfigCalls)
		}
		if !strings.Contains(err.Error(), "no-such-screen-4960") {
			t.Fatalf("trial %d: rejected for the wrong reason, so this test would not "+
				"bind the property: %v", i, err)
		}
	}
}

// TestValidZoneScreenRefStillReachesZoneCompile_4960 is the over-reach guard.
//
// The sweep must reject ONLY an unresolvable reference. A config whose zones all
// name a profile that exists must still reach compileZones and be programmed —
// otherwise the fix would be a blanket refusal to compile any config using
// screen profiles at all, which every zone in the fixture above does.
//
// It stays GREEN under the revert, which is what separates it from a
// restatement of the fix.
func TestValidZoneScreenRefStillReachesZoneCompile_4960(t *testing.T) {
	cfg := zoneScreenPrePassConfig()
	delete(cfg.Security.Zones, "zone-bad-screen")

	dp := &recordingDP{}
	_, err := CompileConfig(dp, cfg, false)

	// recordingDP's tripwire halts the compile at the first SetZoneConfig, so a
	// config that gets that far is one that the pre-pass ACCEPTED.
	if err == nil || !strings.Contains(err.Error(), errStopBeforeHostReconcile.Error()) {
		t.Fatalf("a config whose zones all reference an EXISTING screen profile did "+
			"not reach compileZones — the new sweep is rejecting valid configs. want "+
			"the SetZoneConfig tripwire, got: %v", err)
	}
	if dp.zoneConfigCalls != 1 {
		t.Errorf("want exactly 1 SetZoneConfig call (the tripwire fires on the first "+
			"zone), got %d", dp.zoneConfigCalls)
	}
}

// TestZoneScreenSweepSkipsEmptyAndNilZones_4960 is the second over-reach guard.
//
// The sweep must reject exactly what the loop rejects and no more. Two shapes
// the loop tolerates must stay tolerated: a zone with NO screen-profile at all
// (the overwhelmingly common case), and a nil zone slot — reachable on the
// tolerant / HA-peer-sync config paths, which programZoneMaps explicitly skips.
// A sweep that dereferenced the nil slot would panic the apply; one that
// demanded a profile of every zone would refuse nearly every real config.
//
// Stays GREEN under the revert.
func TestZoneScreenSweepSkipsEmptyAndNilZones_4960(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"no-screen": {Name: "no-screen"},
		"nil-slot":  nil,
	}

	if err := validateZoneScreenReferences(cfg, newValidationResult()); err != nil {
		t.Fatalf("the sweep rejected a zone with no screen-profile and/or a nil zone "+
			"slot, both of which programZoneMaps tolerates: %v", err)
	}
}
