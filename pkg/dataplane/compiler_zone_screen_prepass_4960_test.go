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
// per range, so with the fix reverted the offending zone is sometimes visited
// FIRST; the compile then aborts before any mutation, which looks exactly like
// a pass. One iteration would therefore be a FLAKY revert probe that reports
// green on broken code a fraction of the time.
//
// The per-trial slip rate is MEASURED, not derived (#6894 r5 F3). Both of the
// numbers this comment used to carry were wrong, in opposite directions. It is
// not a "coin flip" — that would be 0.5. Nor is it the uniformity-derived 1/N:
// the fixture holds NINE zones (eight valid plus the offender), and Go's map
// range picks a random start bucket and a random offset within it, so which key
// lands first is not uniform over the nine. Reverting BOTH halves of the fix
// and running the single-trial compile 200,000 times gives
//
//	slip = 12632/200000 = 0.0632 per trial      (uniform 1/9 would be 0.1111)
//
// so k=24 trials leaves a reverted build passing with probability ~0.0632^24,
// about 1e-29. The old text said "N^-k; at N=8 ... ~10^-21", which had the
// wrong denominator (8, counting only the valid zones) AND the wrong model.
// The guard is in fact stronger than the claim it used to make, but a guard
// whose stated strength is not the measured one is not a guard anyone can
// reason about.
//
// The randomisation is not noise to be suppressed here — it is half the
// finding, because it means the defect's blast radius differs run to run on the
// same config.

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

	// FIXTURE FLOOR (#6894 r5 F3). Nothing tied the trial count to the fixture,
	// so the probe's whole premise — that a REVERTED build has zones left to
	// program before it reaches the offender — rested on the zone loop above
	// staying populated. Trim that loop to zero and the map holds only the
	// offender: it is visited first every time, `zoneConfigCalls` is always 0,
	// and this test passes 24/24 on BROKEN code. The randomised order that makes
	// the probe need many trials is exactly what makes it silently vacuous when
	// the fixture shrinks, so assert the shape the trial count was chosen for
	// rather than trusting it.
	probe := zoneScreenPrePassConfig()
	const wantValidZones = 8
	if got := len(probe.Security.Zones); got != wantValidZones+1 {
		t.Fatalf("fixture carries %d zones, expected %d (%d valid + 1 offender) — "+
			"the 0.0632 per-trial slip rate and the %d-trial count were both "+
			"derived for that shape, and with fewer valid zones the offender is "+
			"visited first more often (at zero valid zones, ALWAYS), so this probe "+
			"would pass on a reverted build",
			got, wantValidZones+1, wantValidZones, trials)
	}
	programmable := 0
	for name, z := range probe.Security.Zones {
		if name != "zone-bad-screen" && z != nil && len(z.Interfaces) > 0 {
			programmable++
		}
	}
	if programmable != wantValidZones {
		t.Fatalf("only %d of the valid zones carry interfaces, expected %d — a zone "+
			"with no interfaces is programmed without reaching mapZoneInterface, so "+
			"it cannot witness the host mutation this probe exists to catch",
			programmable, wantValidZones)
	}

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

// TestPrePassReportsTheSamePhaseProductionWould_4960 binds the phase-table
// ORDER behaviourally, which TestValidationPhaseTableMatchesDocumentedCoverage
// structurally cannot (#6894 r5 F5).
//
// That test compares validationPhases against a hand-written `want` list. Both
// are written by the same person in the same round, so when the table's order
// diverged from CompileConfig's the two agreed with each other and were wrong
// together — the table said "in the same order CompileConfig runs them" while
// "zone screen references" sat eighth, behind "address book", even though
// production reaches it first (validateZoneScreenReferences is the first thing
// inside compileZones, and compileZones is the first phase).
//
// This asserts the property the order exists FOR, against a config that trips
// BOTH phases at once: the pre-pass must name the phase production would have
// aborted in. With the row misplaced, the pre-pass blames "address book" for a
// config production would reject on the screen reference, so the operator is
// pointed at the wrong stanza.
//
// RED on revert: move the "zone screen references" row back after "screen
// profiles" and this fails with the address-book phase in the error.
func TestPrePassReportsTheSamePhaseProductionWould_4960(t *testing.T) {
	cfg := zoneScreenPrePassConfig()
	// Second defect, in a phase whose row sits EARLY in the table. An
	// address-book entry whose value is not parseable as a prefix is rejected by
	// compileAddressBook's own resolution, independent of the dataplane.
	cfg.Security.AddressBook = &config.AddressBook{
		AddressSets: map[string]*config.AddressSet{
			"set-with-missing-member": {
				Name:      "set-with-missing-member",
				Addresses: []string{"no-such-address-4960"},
			},
		},
	}

	err := validateBeforeMutate(cfg)
	if err == nil {
		t.Fatal("a config with BOTH a stale zone screen reference and a broken " +
			"address-book set passed the pre-pass — neither phase rejected, so " +
			"this test cannot observe which one reports first")
	}

	// PRODUCTION's order: compileZones runs first, and validateZoneScreenReferences
	// runs at the top of it, so the screen reference is what an un-pre-passed
	// apply would abort on. Assert the pre-pass agrees.
	if !strings.Contains(err.Error(), "zone screen references") {
		t.Errorf("the pre-pass reported %q, but production aborts in compileZones "+
			"on the zone screen reference before it ever reaches compileAddressBook "+
			"— the phase table's order has drifted from CompileConfig's and the "+
			"pre-pass now names a different phase than the operator would otherwise "+
			"have seen (#6894 r5 F5)", err.Error())
	}
}

// TestScreenIDsKeySetMirrorsConfig_4960 pins the construction invariant that
// makes the two zone->screen resolution sites REDUNDANT (#6894 r5 F2).
//
// buildZoneConfig (compiler_iface.go) resolves a zone's screen-profile
// reference against result.ScreenIDs; mapZoneInterface resolves the SAME
// reference against cfg.Security.Screen. A review round observed that neither
// site is independently bound — remove either and the suite stays green — and
// asked for a test that separates them.
//
// It cannot be written honestly, and this test is why. assignScreenIDs
// (compiler.go) populates ScreenIDs BY RANGING cfg.Security.Screen, so the two
// key sets are identical by construction and no real config distinguishes the
// sites. Separating them would need a hand-built CompileResult whose ScreenIDs
// disagrees with cfg — a state production cannot produce, i.e. a fixture that
// looks like coverage while testing nothing. (Since validateZoneScreenReferences
// was hoisted to the top of compileZones and checks BOTH sources, both sites are
// additionally backstops the sweep pre-empts.)
//
// The redundancy is therefore load-bearing, and it was implicit. If someone
// later populates ScreenIDs from a second source — a synced peer, a cached
// snapshot, an id reserved for a profile not in this config — the two sites stop
// being redundant, the "structurally impossible to bind independently" reasoning
// above becomes FALSE, and the missing independent binding becomes a real gap.
// This test is what fails at that moment instead of the comment quietly rotting.
func TestScreenIDsKeySetMirrorsConfig_4960(t *testing.T) {
	for _, tc := range []struct {
		name    string
		screens map[string]*config.ScreenProfile
	}{
		{"empty", map[string]*config.ScreenProfile{}},
		{"one", map[string]*config.ScreenProfile{"a": {Name: "a"}}},
		{"several", map[string]*config.ScreenProfile{
			"zeta": {Name: "zeta"}, "alpha": {Name: "alpha"}, "mid": {Name: "mid"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.Screen = tc.screens
			result := newValidationResult()
			assignScreenIDs(result, cfg)

			if len(result.ScreenIDs) != len(cfg.Security.Screen) {
				t.Fatalf("ScreenIDs has %d entries, cfg.Security.Screen has %d — the "+
					"two key sets have diverged, so the zone->screen reference no "+
					"longer resolves identically against the compiled map and the raw "+
					"config. The two resolution sites (compiler_iface.go) are no "+
					"longer redundant and each now needs its own binding (#6894 r5 F2)",
					len(result.ScreenIDs), len(cfg.Security.Screen))
			}
			for name := range cfg.Security.Screen {
				if _, ok := result.ScreenIDs[name]; !ok {
					t.Errorf("profile %q is in cfg.Security.Screen but not ScreenIDs — a "+
						"zone naming it resolves at the raw-config site and FAILS at the "+
						"compiled-map site, so which site runs first now changes the "+
						"verdict (#6894 r5 F2)", name)
				}
			}
			for name := range result.ScreenIDs {
				if _, ok := cfg.Security.Screen[name]; !ok {
					t.Errorf("ScreenIDs carries %q, which cfg.Security.Screen does not — "+
						"ScreenIDs is being populated from a SECOND source. The two "+
						"resolution sites are no longer redundant: a zone naming %q now "+
						"passes the compiled-map check and fails the raw-config one. "+
						"Give each site its own test and correct the redundancy "+
						"reasoning above (#6894 r5 F2)", name, name)
				}
			}
		})
	}
}

// TestCompileZonesRejectsStaleScreenRefWhateverTheCallerDid_4960 binds the
// hoist's OWN claim (#6894 r6 F2).
//
// `compileZones` opens with `validateZoneScreenReferences`, and its comment says
// that placement "makes it structurally impossible for any zone to mutate before
// every zone's reference has been checked, WHATEVER THE CALLER DID FIRST".
// Nothing bound that. Deleting the hoist and keeping only the pre-pass row left
// the whole package GREEN, because `compileZones` has exactly one production
// caller and the pre-pass runs ahead of it — so every existing test reaches
// compileZones through a path that already rejected.
//
// That makes the hoist genuinely redundant TODAY and load-bearing for the claim:
// it is what keeps the guarantee true for a future second caller, or if the
// pre-pass row is ever reordered or dropped. A claim of structural impossibility
// needs a test that fails when the structure changes, so this calls
// `compileZones` DIRECTLY — the idiom `compiler_rxvlan_failclosed_5268_test.go`
// already uses — bypassing CompileConfig and therefore the pre-pass entirely.
//
// RED on revert: delete the `validateZoneScreenReferences` call at the top of
// compileZones (leaving the pre-pass row intact) and this fails, because the
// direct call then reaches programZoneMaps and programs zones before the stale
// reference aborts it.
func TestCompileZonesRejectsStaleScreenRefWhateverTheCallerDid_4960(t *testing.T) {
	cfg := zoneScreenPrePassConfig()
	result := newValidationResult()
	// Phase 1/1.5 as CompileConfig runs them: the sweep reads ScreenIDs, which
	// only assignScreenIDs populates, so without this the zone-good references
	// would be unresolvable too and the test would reject for the wrong reason.
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	dp := &recordingDP{}
	err := compileZones(dp, cfg, result)

	if err == nil {
		t.Fatal("#6894 r6: compileZones accepted a stale zone screen reference when " +
			"called DIRECTLY. The guarantee is that its own top-of-function sweep " +
			"rejects whatever the caller did first; reached without the pre-pass, " +
			"nothing checked it")
	}
	if dp.zoneConfigCalls != 0 {
		t.Fatalf("#6894 r6: compileZones programmed %d zone(s) before rejecting the "+
			"stale screen reference. The pre-pass masks this for the single "+
			"production caller, but the hoist's comment claims the property holds "+
			"WHATEVER THE CALLER DID FIRST — reached directly, it does not",
			dp.zoneConfigCalls)
	}
	if !strings.Contains(err.Error(), "no-such-screen-4960") {
		t.Fatalf("#6894 r6: compileZones rejected for the wrong reason, so this test "+
			"does not bind the hoist: %v", err)
	}
}
