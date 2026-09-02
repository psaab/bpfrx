package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8318: the simulator must deny an unzoned INGRESS unconditionally, matching
// the runtime, while an unzoned EGRESS still falls through to default-policy.
//
// THE FIXTURE MUST USE default-policy permit-all, AND THAT IS THE WHOLE POINT.
// Under `deny-all` — the default default — the broken code and the fixed code
// both return Deny for an unknown FromZone, so a deny-all cell passes on the
// BROKEN implementation and proves nothing. permit-all is the only setting on
// which the two implementations disagree, and the disagreement is exactly what
// this issue is.
//
// WHAT DIVERGED, precisely, so this does not read as undoing #3355. Eligibility
// was already correct and is UNCHANGED: an unknown zone on either side is
// excluded from the zone-pair, wildcard and global tiers, mirroring the
// runtime's `from_id != 0 && to_id != 0` gate — which is what `zoneKnown`'s
// "mirrors the runtime UNCONDITIONALLY" comment is about. It is the TERMINAL
// ACTION after that exclusion that differed: the runtime denies on `from_id ==
// 0` without consulting default-policy (#6682), and deliberately does NOT do
// the same for `to_id == 0` because that "would risk black-holing a
// correctly-configured path".
func TestUnzonedIngressDeniesRegardlessOfDefaultPolicy8318(t *testing.T) {
	permitAll := func() *config.Config {
		return &config.Config{Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyPermit,
			Zones:         zones("trust", "untrust"),
		}}
	}

	t.Run("unknown FromZone denies under permit-all", func(t *testing.T) {
		res := Match(permitAll(), Query{
			FromZone: "not-a-zone", ToZone: "untrust", Protocol: "tcp", DstPort: 80,
		})
		if res.Action != config.PolicyDeny {
			t.Fatalf("unknown FromZone must DENY under default-policy permit-all "+
				"(the runtime denies from_id == 0 unconditionally, #6682); got %v",
				ActionString(res.Action))
		}
		if !res.UnzonedIngress {
			t.Error("the result must carry UnzonedIngress so the verdict is not " +
				"misattributed to default-policy in operator-facing output")
		}
		// The reason must not be attributed to the operator's default. On a
		// permit-all box "deny (default)" would name a default that produced no
		// such thing.
		if res.DefaultUsed {
			t.Error("DefaultUsed must be FALSE: its contract is that Action is the " +
				"configured default-policy, and this Deny overrides it")
		}
		if got := res.DisplayAction(); !strings.Contains(got, "ingress zone unknown") {
			t.Errorf("DisplayAction must name the cause, got %q", got)
		}
		if got := res.DisplayAction(); strings.Contains(got, "(default)") {
			t.Errorf("DisplayAction must NOT read as a default verdict, got %q", got)
		}
	})

	// THE OVER-CORRECTION CASE. The runtime explicitly declined to deny on the
	// egress side; denying here would reintroduce the black-holing risk its
	// comment names (#6713: a MAC-less xfrmi egress resolves to 0 for an
	// unrelated reason). If this row ever reports Deny, the fix has been
	// widened past the runtime.
	t.Run("unknown ToZone still uses default-policy under permit-all", func(t *testing.T) {
		res := Match(permitAll(), Query{
			FromZone: "trust", ToZone: "not-a-zone", Protocol: "tcp", DstPort: 80,
		})
		if res.Action != config.PolicyPermit {
			t.Fatalf("unknown ToZone must fall through to default-policy (permit-all) — "+
				"the runtime falls through on to_id == 0 on purpose; got %v",
				ActionString(res.Action))
		}
		if !res.DefaultUsed {
			t.Error("the egress arm IS a default-policy verdict and must say so")
		}
		if res.UnzonedIngress {
			t.Error("UnzonedIngress is the FROM side only")
		}
	})

	// Both unknown: the ingress rule wins, because the runtime's from_id check
	// runs first and returns before the to_id fall-through is reached.
	t.Run("both unknown denies as ingress", func(t *testing.T) {
		res := Match(permitAll(), Query{
			FromZone: "nope", ToZone: "also-nope", Protocol: "tcp", DstPort: 80,
		})
		if res.Action != config.PolicyDeny || !res.UnzonedIngress {
			t.Fatalf("both-unknown must take the ingress deny (the runtime checks "+
				"from_id first and returns); got action=%v unzoned=%v",
				ActionString(res.Action), res.UnzonedIngress)
		}
	})

	// The deny-all rows are the CONTROL that the deny above is not an artifact
	// of the fixture: both sides deny here on broken and fixed code alike, so
	// these rows must stay green throughout and prove nothing on their own.
	// They are here to show the fix did not change the deny-all behaviour.
	t.Run("deny-all unchanged on both sides", func(t *testing.T) {
		denyAll := &config.Config{Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
		}}
		if res := Match(denyAll, Query{FromZone: "nope", ToZone: "untrust", Protocol: "tcp", DstPort: 80}); res.Action != config.PolicyDeny {
			t.Errorf("unknown FromZone under deny-all must still deny, got %v", ActionString(res.Action))
		}
		if res := Match(denyAll, Query{FromZone: "trust", ToZone: "nope", Protocol: "tcp", DstPort: 80}); res.Action != config.PolicyDeny {
			t.Errorf("unknown ToZone under deny-all must still deny (via the default), got %v", ActionString(res.Action))
		}
	})

	// Eligibility is unchanged (#3355): an unknown zone must still not match a
	// from-any/to-any wildcard. Without this row a "fix" that simply made the
	// unknown zone eligible could pass the deny rows by matching a wildcard
	// PERMIT and then being denied for some other reason.
	t.Run("unknown zone is still ineligible for the wildcard tier", func(t *testing.T) {
		wildcard := &config.Config{Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{{
				FromZone: "any", ToZone: "any",
				Policies: []*config.Policy{{
					Name:   "permit-any-any",
					Match:  config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}},
					Action: config.PolicyPermit,
				}},
			}},
		}}
		res := Match(wildcard, Query{FromZone: "nope", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
		if res.Matched {
			t.Fatalf("an unknown FromZone must remain INELIGIBLE for the from-any/to-any "+
				"tier (#3355) — it matched %q", res.PolicyName)
		}
		if res.Action != config.PolicyDeny || !res.UnzonedIngress {
			t.Fatalf("and it must land on the unzoned-ingress deny; got action=%v unzoned=%v",
				ActionString(res.Action), res.UnzonedIngress)
		}
	})
}
