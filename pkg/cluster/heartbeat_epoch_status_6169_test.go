package cluster

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
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
// RED-on-revert: drop any of the FIVE epoch fmt.Fprintf lines from any of the
// three render sites in status.go and TestEveryEpochCounterIsRendered_6669
// fails. The tests below additionally pin the two counters whose rendered text
// carries an operator note.
//
// "EITHER" WAS WRONG, and this header said it: it read "drop either
// fmt.Fprintf", which named two lines when the block had grown to three
// (Epoch session collisions) and now has five. The third was rendered on all
// three surfaces and asserted by NOTHING — all three copies were deletable with
// the package green — which is what a stale count in a RED-on-revert claim
// costs. The guard below is table-driven over every counter so the next one
// added cannot be silently unbound.

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

// wantArmedLatchNote is the EXACT armed-latch note, spelled out here rather than
// read back from epochlessExposureNote — comparing the renderer against itself
// would pass for any string it happened to produce.
const wantArmedLatchNote = "(downgrade latch armed; count is historical)"

// latchNote isolates the note from a rendered status block: everything after the
// epoch-less count on the "Heartbeats without epoch:" line. It returns ok=false
// when that line is missing, so a caller cannot mistake "no line" for "no note".
func latchNote(out string) (note string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Heartbeats without epoch:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "Heartbeats without epoch:"))
		// rest is "<count>" or "<count>  <note>".
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			return strings.TrimSpace(rest[i:]), true
		}
		return "", true
	}
	return "", false
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
// It binds by EXACT EQUALITY against the isolated note, not by a required
// substring plus a blacklist of forbidden ones. A blacklist is only ever as good
// as the phrasings someone thought of: the previous revision required
// "downgrade latch armed" and forbade "now refused" / "frames refused" /
// "are refused", which admits "downgrade latch armed; epoch-less frames
// currently rejected; count is historical" — the same false enforcement claim in
// words the list did not enumerate (verified: `go build` and `go vet` rc=0 and
// this file PASS with the note changed to exactly that).
//
// The claim it forbids is false, not merely imprecise: heartbeatAuthDecision
// short-circuits to dual-accept whenever no local control-link key is
// configured, and UpdateConfig clears controlAuthKey WITHOUT resetting hbAuth.
// Load a legacy unkeyed config leniently, add the key under `commit confirmed`,
// arm the latch, then let the confirmation lapse in the same daemon: the latch
// stays armed while every epoch-less frame is admitted unverified.
//
// RED-on-revert, by mutation of epochlessExposureNote (status.go) — any edit to
// the armed note reds this, which is the point of the equality. The two that
// matter: restoring the historical "epoch-less frames now refused" spelling, and
// the "downgrade latch armed; epoch-less frames currently rejected" hybrid that
// the previous substring form let through. An earlier revision of this comment
// claimed the first of those reds "both the positive and the negative arm"; it
// did not, because the positive arm's t.Fatalf ended the subtest before the
// negative loop ran. There is now one assertion and no such gap.
func assertLatchNoteReportsFactNotEnforcement(t *testing.T, name, out string) {
	t.Helper()
	note, found := latchNote(out)
	if !found {
		t.Fatalf("%s renders no \"Heartbeats without epoch:\" line at all\n"+
			"--- output ---\n%s", name, out)
	}
	if note != wantArmedLatchNote {
		t.Fatalf("%s renders the armed-latch note as %q, want exactly %q.\n"+
			"The note must state a FACT about this node's state, not what it is enforcing: an "+
			"armed latch coexists with dual-accept whenever no control-link key is configured, "+
			"so any wording that promises epoch-less frames are being refused asserts something "+
			"the node does not know.\n--- output ---\n%s", name, note, wantArmedLatchNote, out)
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

// TestEveryEpochCounterIsRendered_6669 binds ALL FIVE epoch counters on ALL
// THREE surfaces that print the "Control link statistics:" block.
//
// The gap it closes: "Epoch session collisions" was rendered on every surface
// and asserted by no test, so all three copies could be deleted with the
// package green. The two #6669 counters added alongside it
// (EpochOutOfBandRejected, EpochAheadOfClockRejected) would have inherited the
// same hole. A counter that is populated but not rendered is documentation, not
// observability — and one that is rendered but unbound is one careless edit
// away from being neither.
//
// ANTI-ALIASING IS THE DISTINCTNESS PRECONDITION, not the labels. Asserting
// "label appears" and "some number appears" would pass with two render lines
// transposed, or with every line printing the same field. So the fixture drives
// each counter to a DIFFERENT non-zero value and each assertion pairs a label
// with that counter's own value; a transposition then reads the wrong number
// and fails. The precondition is asserted, not assumed — if a future change
// makes two of these coincide, the guard weakens silently and the check below
// says so.
//
// RED-on-revert: delete any one of the five fmt.Fprintf epoch lines from any
// one of the three render sites in status.go.
func TestEveryEpochCounterIsRendered_6669(t *testing.T) {
	e := epochStatusEnv(t)

	// Drive every counter to a distinct non-zero value.
	//
	// Order matters: the epochless admits and the out-of-band refusals must
	// happen BEFORE the latch arms, and the collisions and forward-bound
	// refusals after it, because that is the only order in which all five arms
	// are reachable in one Manager.
	const (
		epochlessAdmits = 6
		outOfBandTries  = 2
		downgradeTries  = 3
		aheadTries      = 4
		liveEpoch       = uint64(9_500_000_000_000_000)
	)

	// (1) EpochlessAdmitted — a not-yet-upgraded peer, before any latch.
	e.liveRun(e.captureIncarnation(0xC001, 0, epochlessAdmits), "not-yet-upgraded peer")

	// (2) EpochOutOfBandRejected — an epoch past the year-2200 horizon. Refused
	// by epochUsableAsFloor, so it neither latches nor moves the floor.
	for i := 0; i < outOfBandTries; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0xC100+i), 1, math.MaxUint64)) {
			t.Fatalf("out-of-band epoch %d was admitted", i)
		}
	}

	// (3) The peer upgrades: the latch arms and the floor lands on liveEpoch.
	e.liveRun(e.captureIncarnation(0xC200, liveEpoch, 2), "upgraded peer")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("setup: an accepted epoch-bearing frame must arm the latch")
	}

	// (4) EpochDowngradeRejected — epoch-less frames now that the latch is armed.
	for i := 0; i < downgradeTries; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0xC300+i), 1, 0)) {
			t.Fatalf("epoch-less frame %d admitted after the latch armed", i)
		}
	}

	// (5) EpochSessionCollision — distinct sessions claiming the floor epoch
	// beyond heartbeatEpochSessionsPerEpoch. The latching session already holds
	// one slot, so the first of these fills the budget and the rest collide.
	collisions := 0
	for i := 0; i < heartbeatEpochSessionsPerEpoch+4; i++ {
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0xC400+i), 1, liveEpoch)) {
			collisions++
		}
	}
	if collisions == 0 {
		t.Fatal("setup: no session collisions were produced")
	}

	// (6) EpochAheadOfClockRejected — above the floor AND beyond the forward
	// bound, so only epochWithinForwardBound can refuse it.
	ahead := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
	if !epochUsableAsFloor(ahead) {
		t.Fatalf("fixture broken: %d must be inside the absolute band, or this counts as "+
			"out-of-band instead", ahead)
	}
	for i := 0; i < aheadTries; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0xC500+i), 1, ahead)) {
			t.Fatalf("epoch %d beyond the forward bound was admitted", i)
		}
	}

	st := e.m.HeartbeatStats()
	counters := []struct {
		label string
		value uint64
	}{
		{"Heartbeats without epoch:", st.EpochlessAdmitted},
		{"Epoch downgrades rejected:", st.EpochDowngradeRejected},
		{"Epoch session collisions:", st.EpochSessionCollision},
		{"Epoch out-of-band rejected:", st.EpochOutOfBandRejected},
		{"Epoch ahead of our clock:", st.EpochAheadOfClockRejected},
	}

	// THE PRECONDITION THAT MAKES THIS A GUARD RATHER THAN A LABEL CHECK.
	seen := map[uint64]string{}
	for _, c := range counters {
		if c.value == 0 {
			t.Fatalf("counter %q is 0, so its assertion below cannot distinguish a rendered "+
				"line from an absent one", c.label)
		}
		if prev, dup := seen[c.value]; dup {
			t.Fatalf("counters %q and %q both hold %d — with equal values a transposed pair "+
				"of render lines would still pass, so this guard would not detect one",
				prev, c.label, c.value)
		}
		seen[c.value] = c.label
	}

	renders := map[string]func() string{
		"FormatInformation":            e.m.FormatInformation,
		"FormatStatistics":             e.m.FormatStatistics,
		"FormatControlPlaneStatistics": e.m.FormatControlPlaneStatistics,
	}
	for name, render := range renders {
		t.Run(name, func(t *testing.T) {
			out := render()
			for _, c := range counters {
				got, ok := renderedCounter(out, c.label)
				if !ok {
					t.Errorf("%s does not render %q at all. A counter nobody can read is "+
						"documentation, not observability.\n--- output ---\n%s", name, c.label, out)
					continue
				}
				if got != c.value {
					t.Errorf("%s renders %q as %d, want %d. Either it is printing the wrong "+
						"field or two render lines are transposed.\n--- output ---\n%s",
						name, c.label, got, c.value, out)
				}
			}
		})
	}
}

// renderedCounter returns the integer a status block prints for `label`.
//
// It PARSES rather than matching a formatted string, because the block is
// column-aligned ("Heartbeats without epoch:   6") and some lines carry a
// trailing operator note. Asserting on an exact spelling would couple every
// counter assertion to the padding, so a cosmetic realignment would red every
// guard at once and teach the next reader to loosen them.
func renderedCounter(out, label string) (uint64, bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, label) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, label))
		field := rest
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			field = rest[:i]
		}
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
