package grpcapi

import "testing"

// #8321 finding 16: `GetNATDestination`'s RuleSetSessions was always empty.
//
// `ruleSetSessions` is keyed {ingressZone, egressZone} from the session's REAL
// zones. A DESTINATION rule-set has no `to` clause — the compiler calls only
// `applyNATFromScope`, so `rs.ToZone` is always "" — and a real session's
// egress zone is never "". So the `{FromZone, ""}` lookup could not match, and
// destination-NAT active session counts were reported as absent on every call,
// whatever the traffic.
//
// These cells bind the LOOKUP RULE against the counts structure directly. The
// alternative — standing up a session walk — would need a live conntrack table
// and would test the walk rather than the key mismatch, which is where the
// defect is.

func counts8321(pairs map[natRuleSetKey]int64, fromZone map[string]int64) natSessionCounts {
	return natSessionCounts{ruleSetSessions: pairs, fromZoneSessions: fromZone}
}

// resolve8321 calls the PRODUCTION resolver. It does not reimplement it: a
// test carrying its own copy of the two-step lookup would pass against a
// production copy that had drifted — and drift between a writer and a reader
// of the same key is exactly the defect being fixed here.
func resolve8321(c natSessionCounts, fromZone, toZone string) (int64, bool) {
	return c.ruleSetSessionCount(fromZone, toZone)
}

func TestAToZonelessRuleSetFindsItsSessions8321(t *testing.T) {
	// The real shape: sessions recorded under real egress zones, a rule-set
	// with none.
	c := counts8321(
		map[natRuleSetKey]int64{
			{"trust", "untrust"}: 3,
			{"trust", "dmz"}:     2,
		},
		map[string]int64{"trust": 5},
	)

	cnt, ok := resolve8321(c, "trust", "")
	if !ok {
		t.Fatal("a destination rule-set with no to-zone found NO sessions. Its " +
			"ToZone is always \"\" and the pair index is keyed by the session's " +
			"real egress zone, so the pair lookup can never match — which is why " +
			"RuleSetSessions was empty on every call.")
	}
	if cnt != 5 {
		t.Errorf("count = %d, want 5 — every session entering the from-zone, "+
			"summed across egress zones (3 untrust + 2 dmz)", cnt)
	}
}

func TestAToZoneBearingRuleSetKeepsTheTighterKey8321(t *testing.T) {
	// THE CONTROL. Without it the fix could be "always use the from-zone
	// total", which would silently widen a rule-set that DOES name an egress
	// zone from its pair count to every session entering the from-zone.
	c := counts8321(
		map[natRuleSetKey]int64{
			{"trust", "untrust"}: 3,
			{"trust", "dmz"}:     2,
		},
		map[string]int64{"trust": 5},
	)

	cnt, ok := resolve8321(c, "trust", "untrust")
	if !ok || cnt != 3 {
		t.Errorf("a rule-set naming to-zone untrust must report its PAIR count 3, "+
			"not the from-zone total 5; got %d (ok=%v)", cnt, ok)
	}
}

func TestAFromZoneWithNoSessionsStillReportsAbsent8321(t *testing.T) {
	// Absence must stay distinguishable from zero. The handler only appends a
	// RuleSetSessions row when the lookup reports ok, so a from-zone that has
	// carried no sessions must not fabricate a 0 row — that would be a
	// different wrong answer to the same question.
	c := counts8321(map[natRuleSetKey]int64{}, map[string]int64{})
	if _, ok := resolve8321(c, "trust", ""); ok {
		t.Error("a from-zone with no recorded sessions reported a count; absence " +
			"and zero must stay distinguishable")
	}
}
