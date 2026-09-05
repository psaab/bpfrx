package config

import "testing"

// #8824 second symptom: `security { flow tcp-mss all-tcp 1350; }` committed
// clean with MSS clamping OFF.
//
// The same stanza failed LOUDLY at one elision depth and SILENTLY at the next.
// Depth alone flipped it from fail-closed to fail-open, which is why one
// symptom was reported and this one was not — an operator who writes the
// rejected spelling learns immediately, and one who writes this spelling
// believes clamping is on.
//
//	security { flow { tcp-mss { all-tcp 1350; } } }   1350   worked
//	security { flow tcp-mss all-tcp 1350; }           0      committed, clamped nothing
//
// CAUSE: `inScope("flow","tcp-mss")` was false, so the doubly-elided run
// `[flow tcp-mss all-tcp 1350]` never folded, `compileFlow` walked an empty
// child list, and nothing refused it. Admitting the pair folds the tail and the
// value reaches the compiler. This is the #8763/#8690 class: an unadmitted pair
// means nothing folds, and a compiler reading Children sees an empty body.
//
// THE INVARIANT ASSERTED HERE IS "arrives OR is refused", NEVER "commits".
// A commit-success assertion is VACUOUS BY CONSTRUCTION on this defect: the
// broken spelling committed with err=<nil>. Every row below therefore checks
// the compiled VALUE, and the rejected rows check that they are rejected rather
// than that they are absent — because absent-and-accepted is precisely the bug.
//
// The `mss`-inline spellings are refused at EVERY depth, and that consistency
// is itself the repair for this defect: before it, one depth accepted them and
// silently discarded the value. Whether they should instead be ACCEPTED is a
// separate, disputed question — see TestCompactLeafTCPMSSKeywordStillRejected6564
// and the note on tcpMSSOptionNodes — and is deliberately not settled here.
func TestTCPMSSSurvivesEveryElisionDepth8824(t *testing.T) {
	type got struct {
		all, greIn, greOut int
		rejected           bool
	}
	compile := func(t *testing.T, text string) got {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			return got{rejected: true}
		}
		f := cfg.Security.Flow
		return got{f.TCPMSSAllTCP, f.TCPMSSGreIn, f.TCPMSSGreOut, false}
	}
	pick := func(g got, kind string) int {
		switch kind {
		case "gre-in":
			return g.greIn
		case "gre-out":
			return g.greOut
		default:
			return g.all
		}
	}

	// THE VALUE MUST ARRIVE at every depth, for every affected kind.
	for _, kind := range []string{"all-tcp", "gre-in", "gre-out"} {
		for _, c := range []struct{ name, text string }{
			{"braced(full)", `security { flow { tcp-mss { ` + kind + ` { mss 1350; } } } }`},
			{"braced value", `security { flow { tcp-mss { ` + kind + ` 1350; } } }`},
			{"doubly elided", `security { flow tcp-mss ` + kind + ` 1350; }`},
		} {
			g := compile(t, c.text)
			if v := pick(g, kind); g.rejected || v != 1350 {
				t.Errorf("%s / %s: value=%d rejected=%v, want 1350. A spelling that COMMITS "+
					"with the value absent is a fail-open: the operator configured a clamp, "+
					"the commit succeeded, and forwarded TCP is unclamped — a PMTU blackhole "+
					"on tunnels with no diagnostic", kind, c.name, v, g.rejected)
			}
		}
	}

	// THE `mss`-INLINE SPELLINGS DELIVER AT EVERY DEPTH.
	//
	// These rows asserted REJECTION when this cell was written, because the
	// question was disputed: #6564 pinned the refusal, #8824 disputed it, and
	// nothing in the tree appeared to settle it. It was settled by a row already
	// in the same instrument — the braced `all-tcp { mss 1350; }` is accepted
	// and compiles to 1350, so `mss` cannot be a typo — and the refusals were
	// reversed. See TestCompactLeafTCPMSSKeywordIsAcceptedEverywhere6564 for the
	// full reasoning; kept here as the depth axis of the same fact.
	for _, c := range []struct{ name, text string }{
		{"singly elided", `security { flow { tcp-mss { all-tcp mss 1350; } } }`},
		{"flow braced", `security { flow { tcp-mss all-tcp mss 1350; } }`},
		{"doubly elided", `security { flow tcp-mss all-tcp mss 1350; }`},
	} {
		g := compile(t, c.text)
		if g.rejected || g.all != 1350 {
			t.Errorf("%s `mss` inline: all=%d rejected=%v, want 1350. Every depth must "+
				"deliver the same value; the doubly-elided form previously COMMITTED while "+
				"discarding it, which is why these rows assert the value and not acceptance",
				c.name, g.all, g.rejected)
		}
	}

	// ABSENCE CONTROL: no statement, no clamp, and no rejection. Without this a
	// compiler that hard-coded 1350 would satisfy every row above.
	if g := compile(t, `security { flow { } }`); g.rejected || g.all != 0 {
		t.Errorf("absent: all=%d rejected=%v, want 0 and accepted", g.all, g.rejected)
	}

	// CONTROL: ipsec-vpn is refused for its OWN documented reason, unrelated to
	// elision depth. It is here so that a blanket rejection — which would also
	// satisfy the `mss` rows above — shows up as this row failing too.
	if g := compile(t, `security { flow { tcp-mss { ipsec-vpn 1300; } } }`); !g.rejected {
		t.Error("control: `ipsec-vpn` is expected to be refused for its own reason; if it now " +
			"commits, the change altered more than tcp-mss elision handling")
	}
}
