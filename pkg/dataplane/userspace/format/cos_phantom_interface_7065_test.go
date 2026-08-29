package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7065: a `class-of-service interfaces` stanza whose interface has no
// counterpart under `interfaces` renders a fully-fledged block, indistinguishable
// from a real interface whose CoS is live. It commits clean, and
// buildInterfaceSnapshots walks cfg.Interfaces.Interfaces — so nothing in that
// block reaches the dataplane.
//
// This is the #6858 failure class one command over: an unanswered question
// rendered as a confident answer. cosRewriteRuleEnforcement already refuses to
// do it for rewrite rules and names the dangling reference when it declines;
// this brings the interface block to the same standard.
//
// BOTH polarities are asserted, and the second is the one that matters. A fix
// that printed the advisory unconditionally would satisfy the phantom case and
// be useless — every real interface would carry a "not applied" line. The two
// rows differ in EXACTLY one thing: whether `interfaces ge-9-9-9 unit 0` exists.
func TestPhantomCoSInterfaceIsMarkedNotApplied_7065(t *testing.T) {
	for _, tc := range []struct {
		name          string
		interfaceUnit *config.InterfaceUnit
		wantAdvisory  bool
	}{
		{"phantom: no interfaces stanza", nil, true},
		{"real: interfaces stanza present", &config.InterfaceUnit{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			writeCoSInterfaceHeader(&b, cosInterfaceView{
				name:          "ge-9-9-9.0",
				ifName:        "ge-9-9-9",
				unit:          0,
				interfaceUnit: tc.interfaceUnit,
				cosUnit: &config.CoSInterfaceUnit{
					SchedulerMap:     "sm",
					ShapingRateBytes: 1875000,
				},
			})
			out := b.String()
			got := strings.Contains(out, "not applied")

			if got != tc.wantAdvisory {
				if tc.wantAdvisory {
					t.Errorf("a class-of-service stanza for an interface that is NOT configured "+
						"rendered with no advisory, so it is indistinguishable from a live one. "+
						"buildInterfaceSnapshots walks cfg.Interfaces.Interfaces, so none of "+
						"these bindings reach the dataplane:\n%s", out)
				} else {
					t.Errorf("a class-of-service stanza for a CONFIGURED interface was marked "+
						"not applied. The advisory is unconditional, which makes it noise on "+
						"every real interface and tells an operator nothing:\n%s", out)
				}
			}
			if !tc.wantAdvisory {
				return
			}
			// The REFERENCE must be named, for the reason cosRewriteRuleEnforcement
			// names its own: a bare "not applied" reads as "you forgot to configure
			// it" to an operator who did configure it, just under a name with a typo
			// in it. Quoting `interfaces <name> unit <n>` points at the stanza to fix.
			if !strings.Contains(out, "interfaces ge-9-9-9 unit 0") {
				t.Errorf("the advisory does not quote the dangling reference, so it does not "+
					"say WHICH stanza is missing:\n%s", out)
			}
			// And the bindings must still print. The advisory qualifies the block;
			// suppressing the block would hide the operator's own committed config
			// from the command that exists to show it.
			if !strings.Contains(out, "sm") {
				t.Errorf("the advisory suppressed the configured bindings; it must qualify "+
					"them, not replace them:\n%s", out)
			}
		})
	}
}
