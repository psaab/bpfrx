package cluster

import (
	"strings"
	"testing"
)

// #7367 criterion 1+3: `show chassis cluster status` reported the cluster state
// machine's view and nothing else — no rg_active term, no VRRP term. So the
// #6656 incident, in which node0 showed primary for RG0/RG1/RG2 while carrying
// 1 session and 4,728 rx packets and node1 carried 33 sessions and 4,675,178,
// rendered as a completely healthy cluster.
//
// rgStateMachine.reconcileLocked computes `desired = clusterPri ||
// allMasterLocked()` in non-strict mode, so ownership and forwarding are an OR.
// "Owns the group and forwards nothing" is representable and was unflagged.

func forwardingLine7367(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Forwarding:") {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// primaryManagerWithForwarding7367 builds a manager holding RG0 as PRIMARY and
// reporting fwd as its dataplane state.
func primaryManagerWithForwarding7367(t *testing.T, fwd RGForwarding) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(m, 4)
	m.SetGroupStateForTesting(0, StatePrimary)
	m.SetRGForwardingFunc(func(rgID int) (RGForwarding, bool) {
		if rgID != 0 {
			return RGForwarding{}, false
		}
		return fwd, true
	})
	// Anti-vacuity: the whole comparison below is about a node that OWNS the
	// group. If the fixture is not primary, both renders would be "consistent"
	// for the trivial reason and the test would pass while proving nothing.
	if got := m.GroupStates()[0].State; got != StatePrimary {
		t.Fatalf("fixture must hold RG0 as primary, got %v — the divergence "+
			"under test only exists for an OWNING node", got)
	}
	return m
}

func TestForwardingDivergenceRendersDifferentlyFromHealthyPrimary7367(t *testing.T) {
	healthy := primaryManagerWithForwarding7367(t, RGForwarding{
		Active: true, AllVRRPMaster: true, AnyVRRPMaster: true,
	})
	diverged := primaryManagerWithForwarding7367(t, RGForwarding{
		Active: false, AllVRRPMaster: false, AnyVRRPMaster: false,
	})

	healthyOut, divergedOut := healthy.FormatStatus(), diverged.FormatStatus()
	healthyLine := forwardingLine7367(t, healthyOut)
	divergedLine := forwardingLine7367(t, divergedOut)

	if healthyLine == "" {
		t.Fatalf("no Forwarding: line in the healthy render — the sub-line is "+
			"missing entirely, so nothing below tests a difference:\n%s", healthyOut)
	}
	if divergedLine == "" {
		t.Fatalf("no Forwarding: line in the diverged render:\n%s", divergedOut)
	}

	// The property. Both nodes render an IDENTICAL node row — same priority,
	// same state, same preempt/manual/monitor columns — because ownership is
	// the same in both. Only the forwarding term differs.
	if healthyLine == divergedLine {
		t.Errorf("a node that owns RG0 and forwards NOTHING renders identically "+
			"to a healthy primary:\n  both: %q\n"+
			"this is the #6656 blindness: ownership and forwarding disagree and "+
			"the operator sees a healthy cluster", healthyLine)
	}
	if !strings.Contains(divergedLine, "DIVERGENCE") {
		t.Errorf("the diverged render does not flag a divergence: %q", divergedLine)
	}
	if strings.Contains(healthyLine, "DIVERGENCE") {
		t.Errorf("the HEALTHY render flags a divergence: %q — a marker that "+
			"fires on a consistent node is worse than none, because an operator "+
			"learns to ignore it", healthyLine)
	}
	// Asserting only the ABSENCE of "DIVERGENCE" is not enough, and this is a
	// measured gap rather than a hypothetical: mutating the suffix condition to
	// append UNCONDITIONALLY escaped that assertion, because a consistent
	// verdict renders the word "consistent" and not "DIVERGENCE". The healthy
	// line must carry no verdict suffix at all.
	if strings.Contains(healthyLine, "--") {
		t.Errorf("the HEALTHY render carries a verdict suffix: %q — the suffix "+
			"is for divergences only; appending it to every line trains an "+
			"operator to skip the field that exists to be noticed", healthyLine)
	}
}

// The forwarding line must not be readable as a node row. test-failover.sh
// greps `node1.*primary` over the WHOLE output and deploy-lib.sh awk-matches
// `$1 == "node0"` inside an RG block then reads `$3` as the status; a sub-line
// carrying a node token beside a state token steers a rolling deploy into
// restarting the PRIMARY first (#4009).
func TestForwardingLineIsNotParseableAsANodeRow7367(t *testing.T) {
	for _, tc := range []struct {
		name string
		fwd  RGForwarding
	}{
		{"healthy", RGForwarding{Active: true, AllVRRPMaster: true, AnyVRRPMaster: true}},
		{"owned-not-forwarding", RGForwarding{}},
		{"partial-vrrp", RGForwarding{Active: true, AnyVRRPMaster: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := primaryManagerWithForwarding7367(t, tc.fwd)
			line := forwardingLine7367(t, m.FormatStatus())
			if line == "" {
				t.Fatal("no Forwarding: line")
			}
			for _, tok := range []string{"node0", "node1", "primary", "secondary"} {
				if strings.Contains(line, tok) {
					t.Errorf("forwarding line contains %q, which lets a "+
						"whole-line smoke regex read it as a node row: %q", tok, line)
				}
			}
			if strings.Fields(line)[0] != "Forwarding:" {
				t.Errorf("first field is %q, want Forwarding:", strings.Fields(line)[0])
			}
		})
	}
}

// A nil hook must omit the line, not render a default. Before the daemon wires
// it — and in every existing test — there is no dataplane view to report, and a
// rendered default would assert something false about forwarding.
func TestForwardingLineOmittedWhenNoHook7367(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(m, 4)
	m.SetGroupStateForTesting(0, StatePrimary)
	if line := forwardingLine7367(t, m.FormatStatus()); line != "" {
		t.Errorf("unwired manager rendered a forwarding line: %q", line)
	}
}

// The verdict table. ClassifyRGForwarding was extracted from the render so this
// can assert the classification directly — a guard reachable only through a
// Fprintf has mutation coverage that depends on string formatting, and the
// property here is not a formatting property.
//
// The partial-VRRP rows are the reason this is a table and not two cases. A
// two-row table (all-master vs none) cannot distinguish "reports partial
// mastership" from "reports whatever AllVRRPMaster says", because those two
// implementations agree on every row except the middle one.
func TestClassifyRGForwardingTable7367(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owned bool
		fwd   RGForwarding
		want  RGForwardingVerdict
	}{
		{"owned and forwarding", true,
			RGForwarding{Active: true, AllVRRPMaster: true, AnyVRRPMaster: true},
			RGForwardingConsistent},
		{"not owned and not forwarding", false,
			RGForwarding{}, RGForwardingConsistent},
		{"owned but not forwarding", true,
			RGForwarding{}, RGForwardingOwnedNotForwarding},
		{"forwarding but not owned", false,
			RGForwarding{Active: true, AllVRRPMaster: true, AnyVRRPMaster: true},
			RGForwardingForwardingNotOwned},
		// The middle rows: partial mastership is a defect under EITHER
		// ownership value, so it is classified before the ownership compare.
		// Filing it by ownership would put the same wire condition under two
		// verdicts and hide half of them.
		{"owned, partial vrrp", true,
			RGForwarding{Active: true, AnyVRRPMaster: true},
			RGForwardingPartialVRRP},
		{"not owned, partial vrrp", false,
			RGForwarding{Active: false, AnyVRRPMaster: true},
			RGForwardingPartialVRRP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyRGForwarding(tc.owned, tc.fwd); got != tc.want {
				t.Errorf("ClassifyRGForwarding(%v, %+v) = %v, want %v",
					tc.owned, tc.fwd, got, tc.want)
			}
		})
	}
}
