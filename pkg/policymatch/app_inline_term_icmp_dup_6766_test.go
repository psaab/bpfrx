package policymatch

import (
	"net"
	"strings"
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
// the TOLERANT path.
//
// It also BINDS THE DUPLICATE RECORDING (#6814 gate): without the two checks
// below, deleting the #6766 tracking outright leaves these tests green, because
// the compiled values — and therefore every verdict — are identical whether or
// not the conflict was recorded. The recording is what makes strict reject and
// what puts the operator-visible warning on the tolerant path, so both are
// asserted here rather than assumed.
func inlineICMPDupCfg(t *testing.T, appLine, leaf string) *config.Config {
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
	// The conflict must be RECORDED: strict commit refuses it and names the leaf.
	serr := func() error { _, e := config.CompileConfig(tree); return e }()
	if serr == nil {
		t.Fatalf("strict commit must REJECT the conflicting inline %q — if it does not, "+
			"the #6766 duplicate recording is gone and the narrowing below is "+
			"reachable through a green commit", leaf)
	}
	// The leaf name is matched in its QUOTED form. The rejection text ends with a
	// static enumeration of every trackable leaf —
	// "(destination-port / source-port / ... / icmp-type / icmp-code)" — so a bare
	// substring check for the leaf is satisfied by that boilerplate no matter
	// which leaf actually conflicted, and a swapped label would sail through.
	// Only the identifying occurrence is quoted (`conflicting duplicate
	// "icmp-type" inside`), so quoting is what makes "names the leaf" true.
	if !strings.Contains(serr.Error(), "duplicate") || !strings.Contains(serr.Error(), `"`+leaf+`"`) {
		t.Fatalf("strict rejection should name the duplicate leaf %q (quoted, so the "+
			"static leaf enumeration in the message cannot satisfy this), got: %v", leaf, serr)
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not brick on a conflicting inline ICMP repeat: %v", err)
	}
	// ...and the tolerant path must still SAY so. This is the only signal an
	// operator gets on the path that keeps forwarding, so it is part of the
	// contract these verdict tests characterize.
	warned := false
	for _, w := range cfg.Warnings {
		// Quoted, for the same reason as the strict assertion above.
		if strings.Contains(w, "duplicate") && strings.Contains(w, `"`+leaf+`"`) {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("tolerant path must record a downgrade warning naming %q — the "+
			"narrowing asserted below is otherwise completely silent; warnings: %v",
			leaf, cfg.Warnings)
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
		"set applications application badapp term t1 protocol icmp icmp-type 8 icmp-type 3",
		"icmp-type")

	t.Run("last authored type is the one enforced", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(3), nil))
		if res.DefaultUsed {
			t.Fatalf("ICMP type 3 must be denied by the POLICY, not by a default; got default_used=true action=%v", res.Action)
		}
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
		assertFellThroughToDefaultPermit(t, res, "ICMP type 8 (the FIRST authored icmp-type)")
	})
}

// TestInlineTermICMPCodeDupNarrowsEnforcement_6766 is the icmp-CODE analogue,
// and is the specific gap the strict-rejection tests left open: nothing
// anywhere constrained which conflicting CODE survives.
func TestInlineTermICMPCodeDupNarrowsEnforcement_6766(t *testing.T) {
	// Authored `icmp-code 1` then `icmp-code 2` under a fixed type 3.
	cfg := inlineICMPDupCfg(t,
		"set applications application badapp term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2",
		"icmp-code")

	t.Run("last authored code is the one enforced", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(3), u8(2)))
		if res.DefaultUsed {
			t.Fatalf("ICMP type 3 code 2 must be denied by the POLICY, not by a default; got default_used=true action=%v", res.Action)
		}
		if !res.Matched || res.Action != config.PolicyDeny {
			t.Fatalf("ICMP type 3 code 2 (the LAST authored icmp-code) must hit the deny; "+
				"got matched=%v action=%v default_used=%v. A production edit that "+
				"retained the FIRST conflicting code would land here",
				res.Matched, res.Action, res.DefaultUsed)
		}
	})

	t.Run("first authored code escapes into default permit-all", func(t *testing.T) {
		res := Match(cfg, icmpQuery(u8(3), u8(1)))
		assertFellThroughToDefaultPermit(t, res, "ICMP type 3 code 1 (the FIRST authored icmp-code)")
	})
}

// assertFellThroughToDefaultPermit asserts that a query reached the configured
// default policy and was permitted there.
//
// #6814 gate: `config.PolicyPermit` is the ZERO value of PolicyAction
// (types_security.go), and so is `Matched=false`. An assertion built only on
// "action is permit" is therefore satisfied by a Result that was never
// populated at all — a path that produced NOTHING looks identical to a genuine
// fall-through. `DefaultUsed` is the only field here that carries non-default
// evidence: it is true ONLY because the default-policy branch actually ran. It
// is asserted FIRST for that reason.
//
// `Matched=false` is asserted explicitly rather than left implied, and the shape
// it independently binds is `Matched=true, DefaultUsed=true, Action=permit` — a
// Result claiming BOTH a concrete policy match and a default fall-through, which
// is incoherent and would otherwise pass. It does NOT carry
// `Matched=true, DefaultUsed=false`: that input fails at the `DefaultUsed` check
// above and never reaches here. Stated precisely because the two legs look
// redundant and are not — the mutation that proves this one sets Matched on the
// default-branch Result, and a later reader trimming the "redundant" check would
// delete the only assertion binding it.
func assertFellThroughToDefaultPermit(t *testing.T, res Result, what string) {
	t.Helper()
	if !res.DefaultUsed {
		t.Fatalf("%s must FALL THROUGH to default-policy permit-all: want DefaultUsed=true, "+
			"got default_used=false matched=%v action=%v. DefaultUsed is the only "+
			"non-zero-valued evidence that the default branch ran at all — permit and "+
			"unmatched are both zero values and prove nothing on their own",
			what, res.Matched, res.Action)
	}
	if res.Matched {
		t.Fatalf("%s must not match a concrete policy: want Matched=false, got matched=true "+
			"action=%v (a policy PERMIT is not the same outcome as falling through)",
			what, res.Action)
	}
	if res.Action != config.PolicyPermit {
		t.Fatalf("%s reached the default policy but was not permitted: action=%v", what, res.Action)
	}
}
