package configstore

import (
	"strings"
	"testing"
)

// #9421, channel 4. The three in-package config channels (SchemaValidate,
// CompileConfig, CompileConfigLenient) are asserted in pkg/config by
// TestScreenFamilyPackedTailBothShapes9421; this is the OPERATOR path —
// configstore.CheckText, the gate every commit and every `xpfd check-config`
// actually goes through — asserted against the same statements.
//
// The channel matters here more than usual. Before the fix the four channels
// DISAGREED about one config: strict CompileConfig rejected the flat spelling
// with the #1960/#3318 message while accepting and silently discarding the
// identical hierarchical one. A probe on any single channel would have
// supported a much larger claim than it could carry.
const screenBase9421 = "system { host-name p; }\n"

func screenCheck9421(t *testing.T, body string) error {
	t.Helper()
	_, err := CheckText(screenBase9421+"security { screen { ids-option P { "+body+" } } }", -1)
	return err
}

// The brace-elided family spelling must COMMIT and arm the check. Before the
// fix it committed clean with the check compiled DISABLED.
func TestScreenFamilyElidedCommitsAndArms9421(t *testing.T) {
	for _, body := range []string{
		"icmp ping-death;",
		"ip tear-drop;",
		"tcp land;",
		"udp flood threshold 900;",
		"limit-session source-ip-based 100;",
	} {
		cfg, err := CheckText(screenBase9421+"security { screen { ids-option P { "+body+" } } }", -1)
		if err != nil {
			t.Fatalf("%q rejected by the operator commit path: %v", body, err)
		}
		p := cfg.Security.Screen["P"]
		if p == nil {
			t.Fatalf("%q: no screen profile compiled", body)
		}
		armed := p.ICMP.PingDeath || p.IP.TearDrop || p.TCP.Land ||
			p.UDP.FloodThreshold > 0 || p.LimitSession.SourceIPBased > 0
		if !armed {
			t.Fatalf("%q committed clean with NOTHING armed — the check the "+
				"operator configured compiled disabled (#9421)", body)
		}
	}
}

// The bracketed multi-token spelling and an unsupported leaf must be REFUSED at
// the operator commit path, naming the operator's own tokens. `icmp` is a
// container of sibling flags declared with `children` and no `multi:`, so a
// bracketed list is not a shape this grammar has; the flat path already refused
// it and the hierarchical path silently discarded it.
func TestScreenFamilyBracketedRefusedAtCommit9421(t *testing.T) {
	cases := map[string]string{
		"icmp [ ping-death fragment ];": "icmp ping-death fragment",
		"tcp [ syn-fin land ];":         "tcp syn-fin land",
		"tcp bogus-check;":              "tcp bogus-check",
	}
	for body, want := range cases {
		err := screenCheck9421(t, body)
		if err == nil {
			t.Fatalf("%q accepted by the operator commit path — a screen "+
				"spelling that enforces nothing committed clean (#9421)", body)
		}
		if !strings.Contains(err.Error(), "`"+want+"` is not a supported screen option") {
			t.Fatalf("%q rejected, but not by the #3318 unknown-leaf gate naming "+
				"the operator's tokens (%q): %v", body, want, err)
		}
	}
}

// Positive control: the NESTED spelling of the same checks has always worked and
// must keep working, so the refusals above are a measurement of the packed tail
// rather than of the fixture.
func TestScreenFamilyNestedStillCommits9421(t *testing.T) {
	cfg, err := CheckText(screenBase9421+
		"security { screen { ids-option P { icmp { ping-death; fragment; } tcp { land; } } } }", -1)
	if err != nil {
		t.Fatalf("nested control rejected: %v", err)
	}
	p := cfg.Security.Screen["P"]
	if p == nil || !p.ICMP.PingDeath || !p.ICMP.Fragment || !p.TCP.Land {
		t.Fatalf("nested control did not arm the checks: %+v", p)
	}
}
