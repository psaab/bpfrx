package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #8177: the surfaces #7776 did not cover.
//
// These cells deliberately drive MORE THAN ONE surface from ONE config rather
// than checking each in its own cell. Four renderers that must agree about one
// system-wide fact is exactly the shape where per-surface cells pass
// individually while the surfaces say different things — and a cell written in
// the same sitting as the renderer it checks inherits that renderer's premise,
// so its agreement is not evidence. Comparing two renderings of one config is
// the part that can disagree.

// Three of the four surfaces live in this package, so one config can reach
// them: the hit-count text (#7776, row 2), the detail text (row 4), and the
// structured GetPolicies (row 5).
func TestPolicyStatsDisabledSurfacesAgree_8177(t *testing.T) {
	s := &Server{store: newStatsDisabledGRPCStore(t), dp: &warmupPolicyGRPCDP{Manager: dataplane.New()}}

	var hitBuf, detailBuf strings.Builder
	s.showPoliciesHitCount("", &hitBuf)
	s.showPoliciesDetail("", &detailBuf)
	hit, detail := hitBuf.String(), detailBuf.String()

	// The WORDING is the shared invariant; the COUNT is not, and finding that
	// out is what this cell was for. The two surfaces render different row
	// populations: the hit-count table includes the implicit default policy and
	// the detail view does not render one at all. So the correct note is 2 here
	// and 1 there, and an assertion that forced them equal would have been
	// demanding a wrong number from one of the two.
	const tail = " policy count(s) read 0 because policy-stats is disabled " +
		"system-wide, not because no traffic matched (enable with " +
		"`set security policy-stats system-wide enable`, or add `count` to an " +
		"individual policy)"

	if !strings.Contains(hit, "note: 2"+tail) {
		t.Errorf("hit-count text (row 2) does not carry the shared note with its own count. "+
			"2 = the count-less `plain-allow` plus the implicit default policy; the two "+
			"`count`-bearing rules ARE read with the knob off, so counting them would make "+
			"the note false.\ngot:\n%s", hit)
	}
	if !strings.Contains(detail, "note: 1"+tail) {
		t.Errorf("detail text (row 4) does not carry the shared note with its own count. "+
			"1 = `plain-allow`; this surface renders no default-policy row. It had NO "+
			"trailing-note mechanism at all before #8177 — it omitted the Session statistics "+
			"block entirely, which #7016's own comment calls indistinguishable from "+
			"policy-stats being off.\ngot:\n%s", detail)
	}
	// The sentence itself must be one sentence across the surfaces. Four
	// renderers describing one state in four wordings is what #7776 set out to
	// stop, and it is the part that silently drifts — the counts cannot, because
	// each is checked above against its own population.
	if strings.Count(hit, tail) == 0 || strings.Count(detail, tail) == 0 {
		t.Error("the two text surfaces do not share the note wording verbatim")
	}

	// The structured surface must report the same fact in its own idiom.
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	if resp.PolicyStatsEnabled {
		t.Error("GetPolicies reports policy_stats_enabled=true while the two text surfaces " +
			"rendered from the SAME config both say it is disabled")
	}
}

// THE DEFECT ITSELF. For a rule with count=false, "stats on" and "stats off"
// used to serialize byte-identically: count=false, hit_counters_unavailable
// =false, hit_packets=0 in both. In the first the zero is authoritative; in the
// second nothing was measured. This asserts the two are now distinguishable.
//
// It compares two RENDERINGS rather than checking one field's value, so it
// fails if the field is present but constant — which is what a field wired to a
// literal, or to the wrong config, would look like.
func TestStatsOnAndStatsOffAreDistinguishable_8177(t *testing.T) {
	off := &Server{store: newStatsDisabledGRPCStore(t), dp: &warmupPolicyGRPCDP{Manager: dataplane.New()}}
	on := &Server{store: newSchedulerCounterGRPCStore(t), dp: &warmupPolicyGRPCDP{Manager: dataplane.New()}}

	respOff, err := off.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies(off): %v", err)
	}
	respOn, err := on.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies(on): %v", err)
	}

	// Premise: the two fixtures differ ONLY in the policy-stats stanza. If they
	// ever stop sharing their policy set this cell is comparing two different
	// configs and proves nothing about the knob.
	if len(respOff.Policies) != len(respOn.Policies) {
		t.Fatalf("premise broken: fixtures carry different policy sets (%d vs %d zone-pair blocks); "+
			"this cell only isolates the knob when everything else matches",
			len(respOff.Policies), len(respOn.Policies))
	}
	if respOff.PolicyStatsEnabled == respOn.PolicyStatsEnabled {
		t.Fatalf("stats-off and stats-on responses report the same policy_stats_enabled (%v). "+
			"A consumer still cannot tell an authoritative zero from an unmeasured one, which is "+
			"the whole of #8177", respOff.PolicyStatsEnabled)
	}
}

// The shipped contract must be UNCHANGED. Setting hit_counters_unavailable for
// the stats-off case was the tempting shortcut: it needs no new field and makes
// the two states differ. It would also contradict the proto comment, which
// reserves that flag for counter-ELIGIBLE rules and assigns not-eligible to
// count=false — lying to exactly the consumer that implemented the stated split
// correctly.
func TestStatsDisabledDoesNotRepurposeHitCountersUnavailable_8177(t *testing.T) {
	s := &Server{store: newStatsDisabledGRPCStore(t), dp: &warmupPolicyGRPCDP{Manager: dataplane.New()}}
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	seen := 0
	for _, pi := range resp.Policies {
		for _, r := range pi.Rules {
			if r.Count {
				continue
			}
			seen++
			if r.HitCountersUnavailable {
				t.Errorf("rule %q is not counter-eligible (count=false) yet carries "+
					"hit_counters_unavailable. That flag is documented as counter-ELIGIBLE "+
					"but unanswered; reusing it for the stats-off case redefines a shipped "+
					"field instead of adding one, and breaks the consumer that read the "+
					"proto comment", r.Name)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no count=false rules in the fixture, so this cell asserted nothing")
	}
}

// CONTROL: with policy-stats ENABLED the detail surface must not print the
// note. Without this, an unconditional note passes the cell above and is a new
// false statement in place of the one #8177 removed.
func TestDetailOmitsTheStatsDisabledNoteWhenEnabled_8177(t *testing.T) {
	s := warmupPolicyGRPCServer(t) // its store carries `system-wide enable`
	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	if out := buf.String(); strings.Contains(out, "policy-stats is disabled") {
		t.Errorf("detail text prints the stats-disabled note while policy-stats is ENABLED; "+
			"the note is unconditional and therefore says nothing. got:\n%s", out)
	}
}

// The detail surface's read condition carries `readPolicy != nil` as well, so
// its else branch is reachable a SECOND way: an unloaded dataplane. Both terms
// of the `!statsEnabled && !pol.Count` guard are load-bearing on that path, and
// every cell above is blind to it because their dataplane is loaded.
//
// Written because a mutation ESCAPED — replacing the guard with a bare `else`
// left all of them green, which means they were not testing the guard at all.
// #7776 hit the identical escape one function over and closed it the same way;
// that its twin needed the same cell is the point, since these two renderers
// keep drifting apart.
//
// With policy-stats ENABLED and no dataplane, a bare `else` counts every row and
// prints a note claiming policy-stats is disabled when it is enabled — a new
// false statement in place of the one #8177 removed.
func TestDetailDoesNotBlameStatsWhenTheDataplaneIsUnloaded_8177(t *testing.T) {
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: nil}

	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	if out := buf.String(); strings.Contains(out, "policy-stats is disabled") {
		t.Errorf("detail text blames policy-stats for absent Session statistics caused by an "+
			"UNLOADED dataplane, while policy-stats is ENABLED — the note must name the cause "+
			"it can prove. got:\n%s", out)
	}
}
