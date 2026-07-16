package config

import (
	"strings"
	"testing"
)

// #5963: the NESTED `class-of-service interfaces <if> unit <n>` form (unit as a
// CHILD node) is a DISTINCT grammar slot from the `.unit` SUFFIX references
// #5933 gated. Its schema node (schema_cos.go) carries no keyValidator, so
// SchemaValidate accepts a non-numeric `unit`; the compiler then SILENTLY
// DROPPED it (strconv.Atoi -> continue in compiler_class_of_service.go) — the
// shaper never bound and CompileConfig returned nil, the same mis-bind /
// fail-open class #5829/#5933 closed. The fix routes the identity through the
// canonical CanonicalLogicalUnit normalizer at the CoS parse site: hard-reject
// on commit, warn on the tolerant load / peer-sync path.
//
// Flat-set MUST be built with ParseSetCommand/SetPath (flatTreeFromSets), never
// NewParser (CLAUDE.md "Testing flat set syntax").
//
// FAIL-ON-REVERT (load-bearing): restore the silent `strconv.Atoi(...); if err
// != nil { continue }` at the parse site → the reject test compiles the
// malformed nested unit clean (accept + silent drop) → its assertion goes RED.

// cosBadNestedUnits is the set of malformed nested-unit tokens the CoS parse
// site must reject at commit. The compiler error always quotes the raw token
// via `unit %q`, so `want` is that quoted form regardless of the inner
// ValidateInteger text.
var cosBadNestedUnits = []struct {
	name string
	tok  string
	want string
}{
	{"non-numeric", "abc", `"abc"`},
	{"negative", "-1", `"-1"`},
	{"integer-overflow", "99999999999999999999", `"99999999999999999999"`},
	{"out-of-range", "16386", `"16386"`}, // > MaxLogicalUnit (16385)
}

// TestCoSNestedUnit5963_Reject proves a malformed nested
// `class-of-service interfaces <if> unit <bad>` is REJECTED at strict commit
// (CompileConfig) instead of silently dropped.
func TestCoSNestedUnit5963_Reject(t *testing.T) {
	for _, tc := range cosBadNestedUnits {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set class-of-service interfaces ge-0-0-0 unit "+tc.tok+" shaping-rate 1m")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed nested CoS unit %q (silent shaper drop); want reject", tc.tok)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name the bad unit token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "class-of-service interfaces") {
				t.Fatalf("error must name the subsystem (class-of-service interfaces): %v", err)
			}
		})
	}
}

// TestCoSNestedUnit5963_ValidBinds guards against over-rejection: a VALID nested
// unit still compiles AND binds the shaper (semantics unchanged for the good
// case). unit 0 and unit 100 are both exercised.
func TestCoSNestedUnit5963_ValidBinds(t *testing.T) {
	cases := []struct {
		unit int
		tok  string
	}{
		{0, "0"},
		{100, "100"},
	}
	for _, tc := range cases {
		t.Run("unit-"+tc.tok, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set class-of-service interfaces ge-0-0-0 unit "+tc.tok+" shaping-rate 1m")
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected a valid nested CoS unit %s: %v", tc.tok, err)
			}
			iface := cfg.ClassOfService.Interfaces["ge-0-0-0"]
			if iface == nil {
				t.Fatalf("CoS interface ge-0-0-0 not compiled for valid unit %s", tc.tok)
			}
			u := iface.Units[tc.unit]
			if u == nil {
				t.Fatalf("shaper never bound: iface.Units[%d] is nil for valid unit %s", tc.unit, tc.tok)
			}
			if u.ShapingRateBytes == 0 {
				t.Fatalf("shaping-rate not bound for valid unit %s (got 0 bytes)", tc.tok)
			}
		})
	}
}

// TestCoSNestedUnit5963_LenientWarns proves the tolerant load / peer-sync path
// (CompileConfigLenient) does NOT hard-error on a malformed nested unit: it
// downgrades to a deterministic warning naming the bad token so an already-
// persisted or peer-synced config still BOOTS (#1960 no-brick). The malformed
// unit is inert (the shaper does not bind), exactly as before the gate.
func TestCoSNestedUnit5963_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service interfaces ge-0-0-0 unit abc shaping-rate 1m")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-rejected a malformed nested CoS unit (want warn): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `"abc"`) && strings.Contains(w, "class-of-service interfaces") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no malformed nested-unit warning; got %v", cfg.Warnings)
	}
}
