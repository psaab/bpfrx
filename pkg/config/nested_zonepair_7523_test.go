package config

import (
	"strings"
	"testing"
)

// nested_zonepair_7523_test.go — #7523.
//
// `security policies from-zone X { to-zone Y { ... } }` was accepted at commit
// and silently omitted. Measured before the fix: the nested spelling compiled
// to ZERO zone-pairs and ZERO policies, while the supported combined spelling
// of the same intent compiled to one and one.
//
// An honesty gap, not a parity gap: Junos models ONE combined hierarchy, so
// this is a shape xpf accepts and does not implement.
//
// The failure mode is the dangerous one for a security policy — the operator
// wrote a rule, the box said nothing, and the pair falls through to the default
// policy. Worse, the SUPPORTED spelling already rejects an undefined zone with
// a precise commit error, so silence reads as acceptance.

func compileText7523(t *testing.T, src string) (*Config, error) {
	t.Helper()
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

const zones7523 = `zones { security-zone trust; security-zone untrust; }`

// THE DEFECT.
func TestNestedZonePairIsRejected7523(t *testing.T) {
	_, err := compileText7523(t, `security { `+zones7523+` policies {
    from-zone trust {
        to-zone untrust {
            policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
        }
    }
} }`)
	if err == nil {
		t.Fatal("a NESTED from-zone { to-zone { ... } } committed cleanly. It compiles to " +
			"zero zone-pairs and zero policies, so the operator's rule is not in force and " +
			"the pair falls through to the default policy with nothing said (#7523)")
	}
	for _, want := range []string{"NESTED", "zero zone-pairs", "from-zone trust to-zone untrust"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q, so it does not tell the operator "+
				"what to write instead: %v", want, err)
		}
	}
}

// CONTROL 1 — the SUPPORTED combined block form must still compile, and must
// still produce the policy. Asserting only "no error" would pass for a gate
// that rejected everything AND for a compiler that dropped the policy.
func TestCombinedZonePairStillCompiles7523(t *testing.T) {
	cfg, err := compileText7523(t, `security { `+zones7523+` policies {
    from-zone trust to-zone untrust {
        policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
    }
} }`)
	if err != nil {
		t.Fatalf("the supported combined spelling must still compile: %v", err)
	}
	if len(cfg.Security.Policies) != 1 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("combined spelling compiled %d zone-pairs / %d policies, want 1 / 1 — the "+
			"gate must not disturb what it is contrasted against",
			len(cfg.Security.Policies), len(cfg.Security.Policies[0].Policies))
	}
}

// CONTROL 2 — the FLAT-SET spelling must still compile.
//
// This control exists because the obvious discriminator is wrong. Dumping the
// three node shapes showed flat-set collapses to the SAME shape as the combined
// block form:
//
//	NESTED    Keys=[from-zone trust]                  children=[to-zone]
//	COMBINED  Keys=[from-zone trust to-zone untrust]  children=[policy]
//	FLAT-SET  Keys=[from-zone trust to-zone untrust]  children=[policy]
//
// A gate keyed on `len(Keys)` would have had to special-case a distinction that
// does not exist, and would most likely have rejected flat-set — the spelling
// every `set` command produces.
func TestFlatSetZonePairStillCompiles7523(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	} {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("the flat-set spelling — what every `set` command produces — must still "+
			"compile: %v", err)
	}
	if len(cfg.Security.Policies) != 1 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("flat-set compiled %d zone-pairs / %d policies, want 1 / 1",
			len(cfg.Security.Policies), len(cfg.Security.Policies[0].Policies))
	}
}

// The tolerant ingress must WARN, not brick. An already-persisted or
// peer-synced config carrying this shape enforced nothing before the gate
// existed and enforces nothing now, so refusing to boot on it would be a
// regression in availability with no gain in enforcement (#1960).
func TestNestedZonePairIsLenientOnTheTolerantPath7523(t *testing.T) {
	src := `security { ` + zones7523 + ` policies {
    from-zone trust { to-zone untrust { policy p1 { then { permit; } } } }
} }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not brick on a shape that was already inert: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nested zone pair") {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path accepted the nested shape and said NOTHING. Downgrading "+
			"to a warning is the no-brick contract; downgrading to silence is the defect "+
			"(#7523). warnings=%v", cfg.Warnings)
	}
}

// CONTROL 3 — the fully-nested CONTAINER spelling must still compile.
//
// `from-zone { X { to-zone { Y { ... } } } }` puts the zone names in their own
// containers, so the from-zone node carries `Keys=[from-zone]` — length ONE.
// It is supported and it compiles.
//
// This control exists because the mutation matrix found its absence. Replacing
// the discriminator with "reject when len(fz.Keys) < 4" passed every other test
// in this file while refusing this valid configuration. It is the difference
// between a gate that rejects an unimplemented shape and one that rejects a
// spelling an operator is entitled to use.
func TestFromZoneContainerSpellingStillCompiles7523(t *testing.T) {
	cfg, err := compileText7523(t, `security { `+zones7523+` policies {
    from-zone {
        trust {
            to-zone {
                untrust {
                    policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
                }
            }
        }
    }
} }`)
	if err != nil {
		t.Fatalf("the from-zone CONTAINER spelling is supported and must still compile; "+
			"a len(Keys)-based gate would reject it: %v", err)
	}
	if len(cfg.Security.Policies) != 1 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("container spelling compiled %d zone-pairs / %d policies, want 1 / 1",
			len(cfg.Security.Policies), len(cfg.Security.Policies[0].Policies))
	}
	zp := cfg.Security.Policies[0]
	if zp.FromZone != "trust" || zp.ToZone != "untrust" {
		t.Errorf("container spelling compiled the pair as %q->%q, want trust->untrust",
			zp.FromZone, zp.ToZone)
	}
}
