package config

import (
	"strings"
	"testing"
)

// #5933: the cross-subsystem interface REFERENCES that carry a `.unit` suffix —
// class-of-service, security-zone membership, routing-instance membership —
// parsed the suffix WITHOUT ValidateLogicalUnit, the residual #5829 (which typed
// the `interfaces <if> unit <n>` INSTANCE key) deferred here. A malformed `.unit`
// there silently MIS-BINDS: the CoS shaper never attaches, the zone-membership
// key never matches a real unit, the route-leak member is dropped
// (strings.Cut + strconv.Atoi -> continue). The fix routes every `.unit` suffix
// through the canonical ValidateLogicalUnit at the compiler strict gate
// (validateInterfaceUnitReferencesStrict) — hard-reject on commit, warn on the
// tolerant load / peer-sync path.
//
// Flat-set MUST be built with ParseSetCommand/SetPath (flatTreeFromSets), never
// NewParser (CLAUDE.md "Testing flat set syntax").
//
// FAIL-ON-REVERT (per subsystem, load-bearing): neutralize that subsystem's loop
// in validateInterfaceUnitReferencesStrict → its reject test compiles the
// malformed reference clean → the reject assertion goes RED.

// badUnitTokens is the shared set of malformed logical-unit suffixes each
// subsystem must reject at commit, plus the raw token the error must name.
var badUnitTokens = []struct {
	name string
	tok  string // the ".unit" suffix
	want string // substring the error must contain (the bad raw token)
}{
	{"non-numeric", "x", `"x"`},
	{"negative", "-1", `"-1"`},
	{"integer-overflow", "99999999999999999999", `"99999999999999999999"`},
	{"out-of-range", "16386", `"16386"`}, // > MaxLogicalUnit (16385)
}

// TestUnitRef5933_CoS rejects a malformed `.unit` on a class-of-service
// interface reference and accepts a valid one.
func TestUnitRef5933_CoS(t *testing.T) {
	for _, tc := range badUnitTokens {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set class-of-service interfaces ge-0-0-0."+tc.tok+" shaping-rate 1m")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed CoS interface .unit %q (silent mis-bind); want reject", tc.tok)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name the bad unit token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "class-of-service") {
				t.Fatalf("error must name the subsystem (class-of-service): %v", err)
			}
		})
	}
	// A valid unit suffix compiles (false-reject guard). ge-0-0-0.0 -> unit 0.
	tree := flatTreeFromSets(t, "set class-of-service interfaces ge-0-0-0.0 shaping-rate 1m")
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a valid CoS interface .unit 0: %v", err)
	}
}

// TestUnitRef5933_Zone rejects a malformed `.unit` on a security-zone interface
// member and accepts a valid one. The base interface is defined so the earlier
// zone-interface-DEFINED gate passes and this gate is what fires.
func TestUnitRef5933_Zone(t *testing.T) {
	base := "set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24"
	for _, tc := range badUnitTokens {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, base,
				"set security zones security-zone trust interfaces ge-0-0-0."+tc.tok)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed zone interface .unit %q (silent mis-bind); want reject", tc.tok)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name the bad unit token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "security-zone") {
				t.Fatalf("error must name the subsystem (security-zone): %v", err)
			}
		})
	}
	tree := flatTreeFromSets(t, base,
		"set security zones security-zone trust interfaces ge-0-0-0.0")
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a valid zone interface .unit 0: %v", err)
	}
}

// TestUnitRef5933_RoutingInstance rejects a malformed `.unit` on a
// routing-instance interface member and accepts a valid one.
func TestUnitRef5933_RoutingInstance(t *testing.T) {
	base := []string{
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances vr1 instance-type virtual-router",
	}
	for _, tc := range badUnitTokens {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			cmds := append(append([]string{}, base...),
				"set routing-instances vr1 interface ge-0-0-0."+tc.tok)
			tree := flatTreeFromSets(t, cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed routing-instance interface .unit %q (silent route-leak drop); want reject", tc.tok)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name the bad unit token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "routing-instances") {
				t.Fatalf("error must name the subsystem (routing-instances): %v", err)
			}
		})
	}
	cmds := append(append([]string{}, base...),
		"set routing-instances vr1 interface ge-0-0-0.0")
	tree := flatTreeFromSets(t, cmds...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a valid routing-instance interface .unit 0: %v", err)
	}
}

// TestUnitRef5933_BareInterfaceAccepted guards against over-rejection: a BARE
// interface reference (no `.unit`) in any of the three subsystems must NOT be
// touched by the gate.
func TestUnitRef5933_BareInterfaceAccepted(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
		"set class-of-service interfaces ge-0-0-0 shaping-rate 1m",
		"set security zones security-zone trust interfaces ge-0-0-0",
		"set routing-instances vr1 instance-type virtual-router",
		"set routing-instances vr1 interface ge-0-0-0",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected bare (no .unit) interface references: %v", err)
	}
}

// TestUnitRef5933_LenientWarns proves the tolerant load / peer-sync path
// (CompileConfigLenient) does NOT hard-error on a malformed `.unit` reference: it
// downgrades to a deterministic warning naming the bad token, so an already-
// persisted or peer-synced config still BOOTS (#1960 no-brick). Exercised on all
// three subsystems.
func TestUnitRef5933_LenientWarns(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"cos", []string{"set class-of-service interfaces ge-0-0-0.x shaping-rate 1m"}},
		{"zone", []string{
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0-0-0.x",
		}},
		{"routing-instance", []string{
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
			"set routing-instances vr1 instance-type virtual-router",
			"set routing-instances vr1 interface ge-0-0-0.x",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.cmds...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected a malformed .unit reference (want warn): %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, `"x"`) && strings.Contains(w, "interface unit reference") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no malformed-unit-reference warning; got %v", cfg.Warnings)
			}
		})
	}
}
