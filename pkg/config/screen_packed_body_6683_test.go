package config

import (
	"reflect"
	"testing"
)

// #6683 / #7460: a screen stanza written PACKED must compile identically to the
// same stanza written NESTED.
//
// Both defects were silent and both left the profile LOOKING configured:
// #6683 packed the whole body onto the ids-option node's Keys so every check
// compiled DISABLED, and #7460 packed a sub-knob onto its check's Keys so the
// check armed at the DEFAULT threshold instead of the configured one. In both
// cases `show configuration` displays what the operator wrote and the profile
// binds to a zone normally.

func screenProfile6683(t *testing.T, src string) (*ScreenProfile, error) {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		return nil, err
	}
	for _, s := range cfg.Security.Screen {
		return s, nil
	}
	return nil, nil
}

// screenBoolFlags6683 is every boolean check the screen compiler recognises,
// enumerated rather than sampled: #6683 explicitly warns that a fix closing
// only the `ping-death` it names leaves the same fail-open on the siblings.
var screenBoolFlags6683 = []struct{ fam, leaf string }{
	{"icmp", "ping-death"}, {"icmp", "fragment"},
	{"ip", "source-route-option"}, {"ip", "tear-drop"},
	{"tcp", "land"}, {"tcp", "winnuke"}, {"tcp", "syn-frag"},
	{"tcp", "syn-fin"}, {"tcp", "no-flag"}, {"tcp", "fin-no-ack"},
}

func TestScreenPackedBodyMatchesNested_6683(t *testing.T) {
	for _, f := range screenBoolFlags6683 {
		t.Run(f.fam+"-"+f.leaf, func(t *testing.T) {
			nested, err := screenProfile6683(t,
				`security { screen { ids-option s1 { `+f.fam+` { `+f.leaf+`; } } } }`)
			if err != nil {
				t.Fatalf("nested spelling failed to compile: %v", err)
			}
			packed, err := screenProfile6683(t,
				`security { screen { ids-option s1 `+f.fam+` `+f.leaf+`; } }`)
			if err != nil {
				t.Fatalf("packed spelling failed to compile: %v", err)
			}

			// Anti-vacuity: the nested spelling must actually enable
			// something. Two all-false profiles compare equal, and that is
			// exactly the bug passing as a green.
			if reflect.DeepEqual(*nested, ScreenProfile{Name: nested.Name}) {
				t.Fatalf("the nested spelling enabled nothing — the fixture cannot detect the defect")
			}
			if !reflect.DeepEqual(nested, packed) {
				t.Errorf("packed body compiled differently from nested (#6683)\n nested = %+v\n packed = %+v",
					*nested, *packed)
			}
		})
	}
}

// TestScreenSubKnobSpellingsAgree_7460 covers the THRESHOLD axis.
//
// Every value here is deliberately distinct from the check's default. An
// earlier probe using `threshold 5000` reported a false green because 5000 IS
// the ip-sweep/port-scan default: the bug substitutes the default, so a fixture
// that happens to configure the default cannot see it.
func TestScreenSubKnobSpellingsAgree_7460(t *testing.T) {
	cases := []struct {
		name, fam, knob string
		get             func(*ScreenProfile) int
		def             int
	}{
		{"ip-sweep threshold", "ip", "ip-sweep threshold 7777",
			func(s *ScreenProfile) int { return s.IP.IPSweepThreshold }, defaultIPSweepThreshold},
		{"port-scan threshold", "tcp", "port-scan threshold 4444",
			func(s *ScreenProfile) int { return s.TCP.PortScanThreshold }, defaultPortScanThreshold},
		{"icmp flood threshold", "icmp", "flood threshold 3333",
			func(s *ScreenProfile) int { return s.ICMP.FloodThreshold }, defaultICMPFloodThreshold},
		{"udp flood threshold", "udp", "flood threshold 2222",
			func(s *ScreenProfile) int { return s.UDP.FloodThreshold }, defaultUDPFloodThreshold},
		{"syn-flood attack-threshold", "tcp", "syn-flood attack-threshold 999",
			func(s *ScreenProfile) int { return synFloodAttack7460(s) }, defaultSynFloodAttackThreshold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			knob, rest := splitFirst7460(tc.knob)
			want := lastToken7460(rest)

			leafSrc := `security { screen { ids-option s1 { ` + tc.fam + ` { ` + tc.knob + `; } } } }`
			blockSrc := `security { screen { ids-option s1 { ` + tc.fam + ` { ` + knob + ` { ` + rest + `; } } } } }`
			packedSrc := `security { screen { ids-option s1 ` + tc.fam + ` ` + tc.knob + `; } }`

			for _, s := range []struct{ label, src string }{
				{"leaf", leafSrc}, {"block", blockSrc}, {"packed", packedSrc},
			} {
				prof, err := screenProfile6683(t, s.src)
				if err != nil {
					t.Fatalf("%s spelling failed to compile: %v", s.label, err)
				}
				got := tc.get(prof)
				if got == tc.def && want != tc.def {
					t.Errorf("%s spelling armed the check at the DEFAULT %d instead of the configured %d — "+
						"the configured threshold was silently discarded (#7460)", s.label, tc.def, want)
					continue
				}
				if got != want {
					t.Errorf("%s spelling compiled %d, want %d", s.label, got, want)
				}
			}
		})
	}
}

// TestScreenBareFlagTrailingTokenRejectsInBothSpellings is what makes the ten
// new entries in the #2419 spelling-differential allowlist honest.
//
// Those entries record that the two spellings name a DIFFERENT garbage token
// when a bare flag carries trailing junk — flat-set parks it as a child and
// recordChildExtras names Keys[0] of each child, hierarchically it stays on
// Keys and recordKeyExtras names every one. An allowlist entry asserting that
// difference is harmless is a CLAIM, and this is its proof: the commit decision
// must be REJECT in both spellings. If that ever stops holding, the allowlist
// is hiding a fail-open and this reds instead of the gate going quiet.
func TestScreenBareFlagTrailingTokenRejectsInBothSpellings(t *testing.T) {
	for _, f := range screenBoolFlags6683 {
		t.Run(f.fam+"-"+f.leaf, func(t *testing.T) {
			if _, err := compileSet(t, []string{
				"set security screen ids-option bad " + f.fam + " " + f.leaf + " bogus",
			}); err == nil {
				t.Errorf("flat-set spelling ACCEPTED trailing garbage on the bare flag %s %s", f.fam, f.leaf)
			}
			tree, perrs := NewParser(
				`security { screen { ids-option bad { ` + f.fam + ` { ` + f.leaf + ` bogus; } } } }`).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Errorf("hierarchical spelling ACCEPTED trailing garbage on the bare flag %s %s", f.fam, f.leaf)
			}
		})
	}
}

func synFloodAttack7460(s *ScreenProfile) int {
	if s.TCP.SynFlood == nil {
		return -1
	}
	return s.TCP.SynFlood.AttackThreshold
}

func splitFirst7460(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

func lastToken7460(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n = n*10 + int(s[i]-'0')
		} else {
			n = 0
		}
	}
	return n
}
