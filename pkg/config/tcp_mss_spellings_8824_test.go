package config

import (
	"strings"
	"testing"
)

// #8824: `all-tcp { mss notanint; }` COMMITTED CLEAN, clamped nothing, and
// warned nobody.
//
// selectMSSToken prefers the `mss` child only when it parses, then falls
// through to the flat token. That fall-through is right for the MIXED shape
// `gre-in 1400 { mss bogus; }` — the #1979 precedence, where the flat 1400 is
// what the compiler uses. But with NO flat token there is nothing to fall
// through to, and returning "no value selected" reported "nothing configured"
// for a config that plainly configures one. The gates never saw a token, so
// nothing refused it.
//
// The asymmetry is what makes it a defect rather than a policy: the SAME bad
// token flat (`all-tcp notanint;`) was refused, and an out-of-range value in
// the SAME braced shape (`all-tcp { mss 70000; }`) was refused. Only
// unparseable-and-braced-with-no-flat-token vanished.
//
// It matters because MSS clamping exists to stop PMTU blackholes on tunnels. A
// clamp that silently does not happen is indistinguishable from one that was
// never configured, which is the state an operator believes they have left.
//
// SEPARATELY AND NOT FIXED HERE: `set security flow tcp-mss all-tcp mss 1350`
// is refused, and whether that is correct turns on whether inline `mss` is a
// typo or the flat-set flattening of the braced child.
// TestCompactLeafTCPMSSKeywordStillRejected6564 pins the rejection on the
// former reading; #8824 asserts the latter. Nothing in this tree settles it,
// so it is escalated rather than decided by a change that cannot cite evidence
// for its premise. The assertions below deliberately do NOT cover that
// spelling.
//
// WHAT MUST NOT CHANGE, asserted because a fix that widened acceptance could
// have taken these with it:
//   - the #1979 MIXED-shape precedence: `gre-in 1400 { mss bogus; }` selects
//     the flat 1400, not the discarded child
//   - `all-tcp msss 1350` is still refused
//   - `ipsec-vpn` is still refused for its own, unrelated reason — which is
//     also the CONTROL that the refusals here are attributable to the value
//     rather than to a blanket rejection
func TestTCPMSSUnparseableChildIsRefused8824(t *testing.T) {
	hier := func(t *testing.T, body string) (all, greIn int, rejected bool, err string) {
		t.Helper()
		tree, perrs := NewParser(`security { flow { tcp-mss { ` + body + ` } } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, e := CompileConfig(tree)
		if e != nil || cfg == nil {
			return 0, 0, true, e.Error()
		}
		return cfg.Security.Flow.TCPMSSAllTCP, cfg.Security.Flow.TCPMSSGreIn, false, ""
	}
	flat := func(t *testing.T, cmd string) (all, greIn int, rejected bool, err string) {
		t.Helper()
		tree := &ConfigTree{}
		path, e := ParseSetCommand(cmd)
		if e != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, e)
		}
		if e := tree.SetPath(path); e != nil {
			t.Fatalf("SetPath(%q): %v", cmd, e)
		}
		cfg, e := CompileConfig(tree)
		if e != nil || cfg == nil {
			return 0, 0, true, e.Error()
		}
		return cfg.Security.Flow.TCPMSSAllTCP, cfg.Security.Flow.TCPMSSGreIn, false, ""
	}

	// THE SECOND FIX: an unparseable value is refused, not silently zeroed.
	if _, _, rej, _ := hier(t, `all-tcp { mss notanint; }`); !rej {
		t.Error("`all-tcp { mss notanint; }` COMMITTED. It clamps nothing and warns nobody, " +
			"which is indistinguishable from never having configured a clamp — the " +
			"failure mode MSS clamping exists to prevent")
	}

	// UNCHANGED SPELLINGS — the regression half.
	for _, c := range []struct {
		name          string
		body          string
		wantAll, wGre int
	}{
		{"braced child", `all-tcp { mss 1350; }`, 1350, 0},
		{"flat value", `all-tcp 1350;`, 1350, 0},
		{"braced gre-in", `gre-in { mss 1360; }`, 0, 1360},
		{"absent", ``, 0, 0},
	} {
		all, gi, rej, e := hier(t, c.body)
		if rej || all != c.wantAll || gi != c.wGre {
			t.Errorf("%s: all=%d greIn=%d rejected=%v (%s), want %d/%d — widening acceptance "+
				"must not move a spelling that already worked", c.name, all, gi, rej, e, c.wantAll, c.wGre)
		}
	}

	// MUST STILL BE REFUSED. Each names a different reason, and the ipsec-vpn
	// row is the control: it fails for its OWN documented reason, so a blanket
	// rejection would show up as all four sharing one message.
	for _, c := range []struct{ name, body, wantIn string }{
		{"out of range", `all-tcp 70000;`, "tcp-mss"},
		{"typo instead of mss", `all-tcp msss 1350;`, "tcp-mss"},
	} {
		if _, _, rej, _ := hier(t, c.body); !rej {
			t.Errorf("%s (%s) was ACCEPTED; accepting the flat-set `mss` spelling must not "+
				"turn a bad value into a good one", c.name, c.body)
		}
	}
	_, _, rejIP, errIP := flat(t, "set security flow tcp-mss ipsec-vpn mss 1300")
	if !rejIP || !strings.Contains(errIP, "ipsec-vpn") {
		t.Errorf("control: ipsec-vpn must still be refused for its own reason, got rejected=%v "+
			"err=%q. If this now passes, the change widened more than the spelling", rejIP, errIP)
	}

	// #1979 MIXED-SHAPE PRECEDENCE. The flat token wins when the child does not
	// parse AND a flat token exists — that is the case the fall-through was
	// written for, and the new no-flat-token branch must not have eaten it.
	if _, gi, rej, e := hier(t, `gre-in 1400 { mss bogus; }`); rej || gi != 1400 {
		t.Errorf("mixed shape `gre-in 1400 { mss bogus; }` -> greIn=%d rejected=%v (%s), "+
			"want 1400. The compiler selects the flat token here (#1979); reporting the "+
			"unparseable child instead would false-reject a config that compiles today",
			gi, rej, e)
	}
}
