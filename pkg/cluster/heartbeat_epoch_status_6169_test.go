package cluster

import (
	"strings"
	"testing"
)

// #6169 observability: the epoch-less heartbeat counter is the operator's ONLY
// way to tell whether a cluster is still accepting pre-upgrade-shaped frames,
// and pkg/cluster/README.md instructs them to read it. A counter that is
// populated on an internal Go struct but rendered nowhere is documentation, not
// observability.
//
// These assert the RENDERED string on every surface that prints the "Control
// link statistics:" block, not merely that the struct field increments.
//
// RED-on-revert: drop either fmt.Fprintf from any of the three render sites in
// status.go and the corresponding subtest fails.

// epochStatusEnv drives real frames through the real gate, then renders.
func epochStatusEnv(t *testing.T) *latchEnv {
	t.Helper()
	e := newLatchEnv(t)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
	return e
}

func TestEpochlessCounterIsRendered_6169(t *testing.T) {
	e := epochStatusEnv(t)

	// A not-yet-upgraded peer: 6 authenticated frames admitted WITHOUT an epoch.
	const epochless = 6
	e.liveRun(e.captureIncarnation(0xAA01, 0, epochless), "not-yet-upgraded peer")

	renders := map[string]func() string{
		"FormatInformation":            e.m.FormatInformation,
		"FormatStatistics":             e.m.FormatStatistics,
		"FormatControlPlaneStatistics": e.m.FormatControlPlaneStatistics,
	}
	for name, render := range renders {
		t.Run(name+"_exposure", func(t *testing.T) {
			out := render()
			if !strings.Contains(out, "Heartbeats without epoch:") {
				t.Fatalf("%s does not render the epoch-less heartbeat counter.\n"+
					"pkg/cluster/README.md tells operators to read it; a counter nobody "+
					"can see is documentation, not observability.\n--- output ---\n%s", name, out)
			}
			// The VALUE must be right, not just the label.
			if !strings.Contains(out, "Heartbeats without epoch:   6") {
				t.Fatalf("%s rendered the wrong epoch-less count (want 6)\n--- output ---\n%s", name, out)
			}
			if !strings.Contains(out, "Epoch downgrades rejected:  0") {
				t.Fatalf("%s did not render the downgrade-rejection counter as 0\n--- output ---\n%s", name, out)
			}
			// While the peer is NOT signing epochs, the operator needs to be told
			// what the number means and what action closes it.
			if !strings.Contains(out, "rotate the control-link PSK") {
				t.Fatalf("%s renders the count without the actionable note\n--- output ---\n%s", name, out)
			}
		})
	}

	// The peer upgrades and starts signing. The latch arms on that first
	// epoch-bearing frame — and the exposure the note describes ENDS THERE, not
	// at some later refusal.
	e.liveRun(e.captureIncarnation(0xAA02, 9_800_000_000_000_000, 2), "upgraded peer")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("setup: an accepted epoch-bearing frame must arm the latch")
	}

	// RENDER WITH NOTHING ELSE INJECTED. This is the state the old code got
	// wrong: it inferred the latch from EpochDowngradeRejected, which only moves
	// once a LATER epoch-less frame is actually refused — a frame that may never
	// arrive. Between arming and that frame, status told the operator "replay
	// protection is ring-only" while the latch was refusing.
	//
	// RED-on-revert: restore `s.EpochDowngradeRejected > 0` in
	// epochlessExposureNote and these three subtests fail.
	for name, render := range renders {
		t.Run(name+"_latched_before_any_downgrade", func(t *testing.T) {
			out := render()
			if !strings.Contains(out, "Epoch downgrades rejected:  0") {
				t.Fatalf("%s: this phase must have NO downgrade rejections yet — the point is "+
					"that the latch is armed without one\n--- output ---\n%s", name, out)
			}
			if strings.Contains(out, "rotate the control-link PSK") {
				t.Fatalf("%s reports LIVE epoch-less exposure while the downgrade latch is armed "+
					"and refusing. The note must read the latch, not the rejection counter.\n"+
					"--- output ---\n%s", name, out)
			}
			if !strings.Contains(out, "count is historical") {
				t.Fatalf("%s does not mark the epoch-less count historical once the latch armed\n"+
					"--- output ---\n%s", name, out)
			}
			assertLatchNoteReportsFactNotEnforcement(t, name, out)
		})
	}

	// Now an epoch-less frame does arrive and is refused, moving the counter.
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xAA03, 1, 0)) {
		t.Fatal("epoch-less frame admitted after the latch armed")
	}

	for name, render := range renders {
		t.Run(name+"_after_latch", func(t *testing.T) {
			out := render()
			if !strings.Contains(out, "Epoch downgrades rejected:  1") {
				t.Fatalf("%s did not render the downgrade rejection\n--- output ---\n%s", name, out)
			}
			// The historical count stays visible but is no longer flagged as live
			// exposure — the latch is refusing now.
			if !strings.Contains(out, "Heartbeats without epoch:   6") {
				t.Fatalf("%s lost the historical epoch-less count\n--- output ---\n%s", name, out)
			}
			if strings.Contains(out, "rotate the control-link PSK") {
				t.Fatalf("%s still flags live exposure after the latch armed\n--- output ---\n%s", name, out)
			}
			if !strings.Contains(out, "count is historical") {
				t.Fatalf("%s does not mark the count historical once the latch armed\n--- output ---\n%s", name, out)
			}
			assertLatchNoteReportsFactNotEnforcement(t, name, out)
		})
	}
}

// assertLatchNoteReportsFactNotEnforcement pins the armed-latch note to a
// statement about THIS NODE'S STATE and forbids promoting it into a claim about
// what is being enforced right now.
//
// Why this exists as a separate assertion rather than a wider `Contains`: the
// note used to read "epoch-less frames now refused; count is historical" and now
// reads "downgrade latch armed; count is historical". BOTH spellings contain
// "count is historical", so every pre-existing assertion in this file passes
// identically before and after that change — the guard could not fire on the one
// runtime-visible thing the fix changed. Asserting the surviving substring is
// not asserting the fix.
//
// The claim itself is false, not merely imprecise: heartbeatAuthDecision
// short-circuits to dual-accept whenever no local control-link key is
// configured, and UpdateConfig clears controlAuthKey WITHOUT resetting hbAuth.
// Load a legacy unkeyed config leniently, add the key under `commit confirmed`,
// arm the latch, then let the confirmation lapse in the same daemon: the latch
// stays armed while every epoch-less frame is admitted unverified.
//
// RED-on-revert: restore "epoch-less frames now refused" in
// epochlessExposureNote (status.go) and both the positive and the negative arm
// below fail.
func assertLatchNoteReportsFactNotEnforcement(t *testing.T, name, out string) {
	t.Helper()
	if !strings.Contains(out, "downgrade latch armed") {
		t.Fatalf("%s does not report the armed latch as a fact about this node's state\n"+
			"--- output ---\n%s", name, out)
	}
	for _, overclaim := range []string{"now refused", "frames refused", "are refused"} {
		if strings.Contains(out, overclaim) {
			t.Fatalf("%s promotes the armed latch into a claim about live enforcement (%q). "+
				"An armed latch coexists with dual-accept whenever no control-link key is "+
				"configured, so this asserts something the node does not know.\n"+
				"--- output ---\n%s", name, overclaim, out)
		}
	}
}

// A clean, fully-upgraded cluster must render a quiet 0 with no scary note.
func TestEpochlessCounterQuietWhenClean_6169(t *testing.T) {
	e := epochStatusEnv(t)
	e.liveRun(e.captureIncarnation(0xBB01, 9_900_000_000_000_000, 4), "upgraded peer")

	out := e.m.FormatControlPlaneStatistics()
	if !strings.Contains(out, "Heartbeats without epoch:   0") {
		t.Fatalf("clean cluster should render 0 epoch-less heartbeats\n--- output ---\n%s", out)
	}
	if strings.Contains(out, "rotate the control-link PSK") || strings.Contains(out, "count is historical") {
		t.Fatalf("clean cluster should render no exposure note\n--- output ---\n%s", out)
	}
}
