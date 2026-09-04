package main

import (
	"strings"
	"testing"
)

// #8321 finding 10: `show security policies global` must show ONLY global
// policies over the remote CLI.
//
// `isPolicyFilterKeyword` accepted "global" as a valid subcommand keyword and
// the handler had no branch for it, so the token was validated and then
// dropped — and the query silently widened to the ENTIRE policy database. An
// operator asking which global policies exist got every zone-pair policy too,
// with nothing indicating the filter had been ignored.
//
// This was a LOCAL/REMOTE DIVERGENCE, not a missing feature: the local CLI has
// handled it since #3357 (`globalOnly := args[1] == "global"`,
// cli_show_security_dispatch.go), and the discriminator the fix needs — the
// global group's "*"/"*" zones — was already in the remote renderer for the
// scoped-global case.

func TestGlobalFilterExcludesZonePairPolicies8321(t *testing.T) {
	fake := &fakeBpfrxClient{getPoliciesResp: scopedGlobalPoliciesResp()}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("", "", true); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})

	// The zone-pair policies must be GONE. Before the fix they were all
	// rendered, which is the silent widening.
	if strings.Contains(out, "Rule: zp-allow") || strings.Contains(out, "Rule: zp-dmz") {
		t.Errorf("`global` rendered a ZONE-PAIR policy — the filter was dropped "+
			"and the query widened to the whole database.\n\ngot:\n%s", out)
	}

	// And the global ones must still be there — without this the cell passes
	// against a filter that renders nothing at all, which would be a different
	// wrong answer to the same question.
	if !strings.Contains(out, "Rule: open-global") {
		t.Errorf("`global` dropped the GLOBAL policies too; it must show exactly "+
			"those.\n\ngot:\n%s", out)
	}
}

func TestWithoutGlobalTheZonePairPoliciesStillRender8321(t *testing.T) {
	// THE CONTROL. Without it, every assertion above passes against a renderer
	// that suppresses zone-pair policies unconditionally — which would break
	// the default `show security policies` for every operator.
	fake := &fakeBpfrxClient{getPoliciesResp: scopedGlobalPoliciesResp()}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("", "", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})
	if !strings.Contains(out, "Rule: zp-allow") {
		t.Errorf("without `global` the zone-pair policies must still render; got:\n%s", out)
	}
	if !strings.Contains(out, "Rule: open-global") {
		t.Errorf("without `global` the global policies must still render too; got:\n%s", out)
	}
}

// A SCOPED global (#3148) lives in the "*"/"*" group but carries per-rule
// zones. It is still a GLOBAL policy, so `global` must keep it — which is why
// the globalOnly skip is placed AFTER the global-group branch rather than at
// the top of the loop.
func TestGlobalKeepsAScopedGlobal8321(t *testing.T) {
	fake := &fakeBpfrxClient{getPoliciesResp: scopedGlobalPoliciesResp()}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("", "", true); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})
	if !strings.Contains(out, "Rule: scoped-tu") {
		t.Errorf("`global` dropped a SCOPED global (#3148). It lives in the "+
			"\"*\"/\"*\" group and is a global policy; placing the globalOnly skip "+
			"before the global-group branch would lose it.\n\ngot:\n%s", out)
	}
}

// TestTheHandlerActuallyPassesGlobal8321 binds the WIRING, not the renderer.
//
// Found by mutation: with the three cells above, replacing the handler's
// `args[1] == "global"` with a literal `false` — the defect exactly — left them
// all green, because they call showPoliciesFiltered directly and supply
// globalOnly themselves. A renderer that can filter and a handler that never
// asks it to are indistinguishable from the renderer's side.
//
// This drives the real entry point, so the token has to survive the parse.
func TestTheHandlerActuallyPassesGlobal8321(t *testing.T) {
	fake := &fakeBpfrxClient{getPoliciesResp: scopedGlobalPoliciesResp()}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies", "global"}); err != nil {
			t.Fatalf("handleShowSecurity: %v", err)
		}
	})

	if strings.Contains(out, "Rule: zp-allow") || strings.Contains(out, "Rule: zp-dmz") {
		t.Errorf("`show security policies global` rendered a ZONE-PAIR policy. "+
			"The keyword is accepted by isPolicyFilterKeyword and must reach the "+
			"renderer — dropping it silently widens the query to the entire "+
			"policy database.\n\ngot:\n%s", out)
	}
	if !strings.Contains(out, "Rule: open-global") {
		t.Errorf("`show security policies global` showed no global policies at "+
			"all; got:\n%s", out)
	}
}
