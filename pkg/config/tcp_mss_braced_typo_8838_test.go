package config

import "testing"

// #8838: the SAME typo was loud in one spelling and silent in the other.
//
//	packed  all-tcp msss 1350;      REJECTED
//	braced  all-tcp { msss 1350; }  ACCEPTED, clamp silently 0
//	packed  all-tcp mss;            REJECTED
//	braced  all-tcp { mss; }        ACCEPTED, clamp silently 0
//
// selectMSSToken returned "no token" for a braced body that yields no usable
// value, and every caller reads that as "nothing configured" — so a malformed
// body was indistinguishable from an absent one. That is the #8824/#8835 shape
// with the token ABSENT or MISNAMED rather than unparseable: same path, same end
// state, reached by a different kind of mistake.
//
// THIS CELL EXISTS BECAUSE MY OWN REPORT WAS WRONG. #8837's summary said "typo
// `msss`, `mss` with no value → still refused". That was measured on the PACKED
// spelling and generalised to the braced one, which did not hold — the axis
// under dispute was varied and the undisputed one was left at whatever value was
// in hand. team-lead caught it by running the controls I had asserted rather
// than measured, and bisected to confirm the behaviour was pre-existing rather
// than a regression from #8837.
//
// THE ASSERTION IS THAT BOTH SPELLINGS BEHAVE THE SAME, and it is stated as
// exact outcomes on each rather than as agreement: two spellings that both
// accept-and-zero agree perfectly, which is the state this fixes.
func TestTCPMSSBracedTypoIsRefusedLikePacked8838(t *testing.T) {
	compile := func(t *testing.T, body string) (allTCP, greIn int, rejected bool) {
		t.Helper()
		tree, perrs := NewParser(`security { flow { tcp-mss { ` + body + ` } } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			return 0, 0, true
		}
		return cfg.Security.Flow.TCPMSSAllTCP, cfg.Security.Flow.TCPMSSGreIn, false
	}

	// A malformed body is refused in BOTH spellings. The braced rows are the
	// fix; the packed rows are the reference they now match, and they are
	// asserted here so a future change that made PACKED silent would red too —
	// the asymmetry is the defect, in whichever direction it appears.
	for _, c := range []struct{ name, body string }{
		{"braced, wrong keyword", `all-tcp { msss 1350; }`},
		{"packed, wrong keyword", `all-tcp msss 1350;`},
		{"braced, keyword with no value", `all-tcp { mss; }`},
		{"packed, keyword with no value", `all-tcp mss;`},
		{"braced, unparseable value", `all-tcp { mss notanint; }`},
		{"flat, unparseable value", `all-tcp notanint;`},
	} {
		if all, _, rejected := compile(t, c.body); !rejected {
			t.Errorf("%s (%s) was ACCEPTED with allTCP=%d. A body that says something "+
				"unusable must not be indistinguishable from one that says nothing: the "+
				"operator configured a clamp and got none, with no diagnostic",
				c.name, c.body, all)
		}
	}

	// AN EMPTY BODY IS NOT MALFORMED and must stay accepted. This is the line
	// the fix walks: a body that says nothing versus a body that says something
	// unusable. Without this row the fix could refuse both and still pass every
	// assertion above.
	if all, _, rejected := compile(t, `all-tcp { }`); rejected || all != 0 {
		t.Errorf("`all-tcp { }` -> allTCP=%d rejected=%v, want accepted with 0. An empty "+
			"block configures nothing, which is a legitimate thing to write", all, rejected)
	}

	// THE #1979 MIXED-SHAPE PRECEDENCE, which the new branch sits directly
	// behind: when a flat token exists it wins, and the unusable child is
	// discarded rather than reported. Both variants — unparseable value and
	// wrong keyword — must still compile to the flat value.
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"mixed, unparseable child", `gre-in 1400 { mss bogus; }`, 1400},
		{"mixed, wrong-keyword child", `gre-in 1400 { msss 1; }`, 1400},
	} {
		if _, greIn, rejected := compile(t, c.body); rejected || greIn != c.want {
			t.Errorf("%s (%s) -> greIn=%d rejected=%v, want %d. The flat token wins when one "+
				"exists (#1979); reporting the child here would false-reject a config that "+
				"compiles today", c.name, c.body, greIn, rejected, c.want)
		}
	}

	// AND THE WORKING SPELLINGS ARE UNTOUCHED — the regression half.
	for _, c := range []struct {
		name, body string
		all, greIn int
	}{
		{"braced value", `all-tcp { mss 1350; }`, 1350, 0},
		{"flat value", `all-tcp 1350;`, 1350, 0},
		{"packed keyword", `all-tcp mss 1350;`, 1350, 0},
		{"braced gre-in", `gre-in { mss 1360; }`, 0, 1360},
	} {
		all, greIn, rejected := compile(t, c.body)
		if rejected || all != c.all || greIn != c.greIn {
			t.Errorf("%s (%s) -> all=%d greIn=%d rejected=%v, want %d/%d",
				c.name, c.body, all, greIn, rejected, c.all, c.greIn)
		}
	}
}
