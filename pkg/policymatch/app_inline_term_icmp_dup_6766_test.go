package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6766 review fold — the VERDICT-level guard on inline-term ICMP duplicate
// narrowing.
//
// The strict gate rejects a conflicting `icmp-type` / `icmp-code` repeat inside
// one inline term, but the TOLERANT path (boot load / HA SyncApply) downgrades
// that reject to a warning and keeps enforcing whatever compiled. So on the
// path that actually forwards packets, WHICH of the conflicting values survives
// is an enforcement outcome, not bookkeeping: the surviving value is the only
// one the deny covers, and every other value falls through to
// `default-policy permit-all`.
//
// The pkg/config tests assert on the compiled Application struct. That binds the
// compiler but not the matcher, and it left the icmp-CODE last-writer
// unconstrained entirely: a production edit that retained the FIRST conflicting
// code instead of the last would satisfy every strict-rejection test, because
// those only assert that a conflict is refused, never which value wins when it
// is tolerated. These tests pin the surviving value for type AND code by
// driving the real matcher, so a keep-first regression flips a concrete
// permit/deny verdict rather than a struct field.
//
// RED-on-revert: drop the #6766 duplicate tracking and the strict gate stops
// rejecting, but these tests still hold — they characterize the tolerated
// narrowing, which is the thing the gate exists to prevent. Change the
// surviving value (keep-first instead of keep-last) and every subtest below
// inverts: the value expected to be DENIED is permitted and vice versa.

// inlineICMPDupCfg builds a deny policy referencing an application whose single
// inline term repeats an ICMP leaf with conflicting values, then compiles it on
// the TOLERANT path (the strict path rejects it by design).
func inlineICMPDupCfg(t *testing.T, appLine string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		appLine,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy blockit match source-address any",
		"set security policies from-zone trust to-zone untrust policy blockit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy blockit match application badapp",
		"set security policies from-zone trust to-zone untrust policy blockit then deny",
		// permit-all is what the narrowed-away traffic escapes into. It is the
		// reason the narrowing is a fail-OPEN and not merely a lost match.
		"set security policies default-policy permit-all",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not brick on a conflicting inline ICMP repeat: %v", err)
	}
	return cfg
}

func icmpQuery(icmpType, icmpCode *uint8) Query {
	return Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "icmp",
		ICMPType: icmpType, ICMPCode: icmpCode,
	}
}

// TestInlineTermICMPTypeDupNarrowsEnforcement_6766 pins which conflicting
// icmp-TYPE survives on the tolerant path, at the verdict.
func TestInlineTermICMPTypeDupNarrowsEnforcement_6766(t *testing.T) {
	// Authored `icmp-type 8` then `icmp-type 3`: last-writer-wins keeps 3.
	cfg := inlineICMPDupCfg(t,
		"set applications application badapp term t1 protocol icmp icmp-type 8 icmp-type 3")

	t.Run("last authored type is the one enforced", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(3), nil))
		if !res.Matched || res.Action != config.PolicyDeny {
			t.Fatalf("ICMP type 3 (the LAST authored icmp-type) must hit the deny; "+
				"got matched=%v action=%v default_used=%v. If type 3 is NOT denied "+
				"while type 8 IS, the compiler kept the FIRST conflicting value and "+
				"the last-writer contract these tests pin has inverted",
				res.Matched, res.Action, res.DefaultUsed)
		}
	})

	t.Run("first authored type escapes into default permit-all", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(8), nil))
		if res.Matched && res.Action == config.PolicyDeny {
			t.Fatalf("ICMP type 8 (the FIRST authored icmp-type) was DENIED — the term " +
				"did not narrow to the last value, so this characterization is stale")
		}
		if res.Action != config.PolicyPermit {
			t.Fatalf("ICMP type 8 must fall through to default-policy permit-all "+
				"(this IS the silent narrowing the strict gate prevents); got action=%v "+
				"matched=%v default_used=%v", res.Action, res.Matched, res.DefaultUsed)
		}
	})
}

// TestInlineTermICMPCodeDupNarrowsEnforcement_6766 is the icmp-CODE analogue,
// and is the specific gap the strict-rejection tests left open: nothing
// anywhere constrained which conflicting CODE survives.
func TestInlineTermICMPCodeDupNarrowsEnforcement_6766(t *testing.T) {
	// Authored `icmp-code 1` then `icmp-code 2` under a fixed type 3.
	cfg := inlineICMPDupCfg(t,
		"set applications application badapp term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2")

	t.Run("last authored code is the one enforced", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(3), u8(2)))
		if !res.Matched || res.Action != config.PolicyDeny {
			t.Fatalf("ICMP type 3 code 2 (the LAST authored icmp-code) must hit the deny; "+
				"got matched=%v action=%v default_used=%v. A production edit that "+
				"retained the FIRST conflicting code would land here",
				res.Matched, res.Action, res.DefaultUsed)
		}
	})

	t.Run("first authored code escapes into default permit-all", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(3), u8(1)))
		if res.Matched && res.Action == config.PolicyDeny {
			t.Fatalf("ICMP type 3 code 1 (the FIRST authored icmp-code) was DENIED — " +
				"the surviving code is the first, not the last, inverting the " +
				"last-writer contract this test pins")
		}
		if res.Action != config.PolicyPermit {
			t.Fatalf("ICMP type 3 code 1 must fall through to default-policy permit-all; "+
				"got action=%v matched=%v default_used=%v",
				res.Action, res.Matched, res.DefaultUsed)
		}
	})
}
