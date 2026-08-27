package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// slack_banner_6884_test.go — #6884.
//
// The #4555 tripwire reports HEADROOM (how close the object is to the 1M wall).
// That is not the quantity its own sensitivity rests on. The floor was chosen
// against a 5.3% object; #6676 then freed ~193k insns and the object reached
// 21.58% — at which point the unchanged 3% constant admitted ~186k additional
// insns, one to two whole IPv6 extension-header iterations (87k-106k each),
// landing with the gate green and nothing said.
//
// Nothing detected that drift, and nothing could: headroom rising is
// indistinguishable from a healthy object, which is precisely what it was.
// SLACK is the discriminator, and printing it on every build is what turns a
// silent recalibration into a visible one.

// runBanner6884 drives the real run() with a stubbed verifier and returns
// stdout, so these cells bind what the build actually prints rather than
// re-deriving the string.
func runBanner6884(t *testing.T, stats dataplane.ShimVerifierStats) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	run([]string{"shimverify", "/tmp/candidate.o"}, &stdout, &stderr,
		func(string) string { return "" },
		func(string) (dataplane.ShimVerifierStats, error) { return stats, nil })
	return stdout.String()
}

func TestSlackToFloorInsnsArithmetic6884(t *testing.T) {
	// The real master object, measured on kernel 7.0.13+deb14-amd64.
	master := dataplane.ShimVerifierStats{ProcessedInsns: 784175, InsnLimit: 1000000}
	if got := master.SlackToFloorInsns(3.0); got != 185825 {
		t.Fatalf("SlackToFloorInsns(3.0) = %d, want 185825 (970000 admitted - 784175 used)", got)
	}
	// The fixture is chosen so slack and headroom cannot be confused: headroom
	// is 21.58%, slack is 185825. A cell whose object sat exactly at the floor
	// would make the two agree at zero and prove nothing.
	if hp := master.HeadroomPct(); hp < 21.5 || hp > 21.6 {
		t.Fatalf("fixture drifted: HeadroomPct() = %v, want ~21.58", hp)
	}
}

// TestSlackGoesNegativePastTheFloor6884 pins the refusal-path magnitude. A
// clamp at zero would make "just over" and "catastrophically over" look
// identical at exactly the moment the number is being read to decide what to do.
func TestSlackGoesNegativePastTheFloor6884(t *testing.T) {
	// 990,796 — the object this issue was filed about.
	past := dataplane.ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000}
	got := past.SlackToFloorInsns(3.0)
	if got != -20796 {
		t.Fatalf("SlackToFloorInsns(3.0) = %d, want -20796 (970000 admitted - 990796 used)", got)
	}
}

// TestSlackIsZeroWhenUnmeasured6884 guards the documented caveat. Unmeasured
// returns 0, which is NOT "no slack" — it is "no answer", and the gate refuses
// an unmeasured object on its own.
//
// THE FIXTURES ARE THE POINT, and my first attempt at this cell was worthless.
// It used the zero value, where the guarded and unguarded code return the SAME
// answer: 0*(1-0.03) - 0 == 0 either way. Deleting the `!s.Measured()` guard
// left the cell green — a real escape, caught by the mutation matrix and not by
// review. The zero value is precisely the value the bug falls back to.
//
// Measured() requires BOTH fields positive, so the discriminating fixtures are
// the half-populated ones. The first is the one that matters operationally: a
// stat with a real limit and no count would report ~970,000 insns of slack —
// "enormous room" — at exactly the moment headroom is UNKNOWN, which is the
// #4555 blind spot reproduced inside the instrument built to close it.
func TestSlackIsZeroWhenUnmeasured6884(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stats     dataplane.ShimVerifierStats
		unguarded int // what the arithmetic alone would produce
	}{
		{
			name:      "limit but no processed count",
			stats:     dataplane.ShimVerifierStats{ProcessedInsns: 0, InsnLimit: 1000000},
			unguarded: 970000,
		},
		{
			name:      "processed count but no limit",
			stats:     dataplane.ShimVerifierStats{ProcessedInsns: 784175, InsnLimit: 0},
			unguarded: -784175,
		},
		{
			name:      "zero value",
			stats:     dataplane.ShimVerifierStats{},
			unguarded: 0, // NOT a discriminator — retained only as a boundary case
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.stats.Measured() {
				t.Fatal("precondition: this fixture must be UNMEASURED")
			}
			if got := tc.stats.SlackToFloorInsns(3.0); got != 0 {
				t.Fatalf("SlackToFloorInsns on an unmeasured stat = %d, want 0 "+
					"(the bare arithmetic would give %d, which would read as a "+
					"slack figure while headroom is unknown)", got, tc.unguarded)
			}
		})
	}
}

// TestPassBannerReportsSlack6884 is the WIRING cell.
//
// SlackToFloorInsns is inert unless the banner prints it. Deleting the slack
// operands from the summary leaves every arithmetic cell above green while the
// build says exactly what it said before — which is the condition that let the
// drift go unnoticed in the first place.
func TestPassBannerReportsSlack6884(t *testing.T) {
	stats := dataplane.ShimVerifierStats{ProcessedInsns: 784175, InsnLimit: 1000000}
	out := runBanner6884(t, stats)

	if !strings.HasPrefix(out, "PASS ") {
		t.Fatalf("expected a PASS banner, got %q", out)
	}
	want := strconv.Itoa(stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct))
	if !strings.Contains(out, want+" insns of slack") {
		t.Fatalf("the PASS banner does not report the floor's remaining slack, so a build "+
			"cannot see the tripwire's sensitivity drift (#6884).\nbanner: %s", out)
	}
}

// TestBannerFloorAgreesWithTheGateConstant6884 binds the AGREEMENT rather than
// pinning a literal.
//
// The banner names a floor and the gate enforces one. If the banner ever
// hard-coded "3.0" it would keep printing 3.0 after the constant moved, and the
// number a reader consults to judge sensitivity would describe a threshold that
// is no longer in force — the same class of defect as the "~5.3%" comment this
// issue is about, reintroduced one layer down. Asserting a literal here would
// encode which side I trust; asserting agreement cannot.
func TestBannerFloorAgreesWithTheGateConstant6884(t *testing.T) {
	out := runBanner6884(t, dataplane.ShimVerifierStats{ProcessedInsns: 784175, InsnLimit: 1000000})

	want := fmt.Sprintf("%.1f%% floor", dataplane.UserspaceShimMinVerifierHeadroomPct)
	if !strings.Contains(out, want) {
		t.Fatalf("the PASS banner does not name the floor the gate actually enforces "+
			"(%q); banner and gate have diverged.\nbanner: %s", want, out)
	}
}

// TestSlackTracksTheFloorConstant6884 proves the reported slack is DERIVED from
// the enforced constant, not from a duplicate of its value.
//
// The two previous cells would both pass if the banner computed slack against a
// hard-coded 3.0 while the gate enforced something else. This one varies the
// floor and asserts the arithmetic moves with it, so the derivation is bound
// without needing to mutate a const.
func TestSlackTracksTheFloorConstant6884(t *testing.T) {
	stats := dataplane.ShimVerifierStats{ProcessedInsns: 784175, InsnLimit: 1000000}
	at3 := stats.SlackToFloorInsns(3.0)
	at15 := stats.SlackToFloorInsns(15.0)
	if at15 >= at3 {
		t.Fatalf("a HIGHER floor must leave LESS slack: 3%%=%d, 15%%=%d", at3, at15)
	}
	if at15 != 850000-784175 {
		t.Fatalf("SlackToFloorInsns(15.0) = %d, want %d", at15, 850000-784175)
	}
}

// TestFloorSelfCheckFiresWhenThePropertyBreaks6884 is the self-check's reason
// to exist: the floor's promise is to fire BEFORE the next structural change
// lands, and whether it still does depends on the RELATIONSHIP between the
// floor and the current object — which moves whenever the object does, in the
// direction that looks like good news.
//
// The fixture is the historical condition: a 3%-era slack of 185,825, which is
// more than two of the cheapest structural change. The note must say so.
func TestFloorSelfCheckFiresWhenThePropertyBreaks6884(t *testing.T) {
	var buf bytes.Buffer
	noteFloorNoLongerTripwires(&buf, 185825)

	out := buf.String()
	if out == "" {
		t.Fatal("the floor admitted 185,825 insns — more than two structural changes — and " +
			"the build said nothing. That is the drift #6884 exists to make visible")
	}
	// It must name the structural-change cost, since that is the number the
	// reader has to judge the floor against.
	if !strings.Contains(out, strconv.Itoa(dataplane.UserspaceShimStructuralChangeInsns)) {
		t.Fatalf("the note does not name the structural-change cost it compared against: %s", out)
	}
	// And it must not read as a build failure — the object verified.
	if strings.Contains(strings.ToLower(out), "reject") {
		t.Fatalf("the note reads as a refusal, but the object PASSED: %s", out)
	}
}

// TestFloorSelfCheckSilentWhenThePropertyHolds6884 is the PAIRED control, and
// it is the cell that makes the one above mean something: without it, "print a
// note" is satisfied by a note that prints unconditionally, which would fire on
// every healthy build and be tuned out within a week.
//
// 65,825 is the real slack at the 15% floor against master's measured 784,175.
func TestFloorSelfCheckSilentWhenThePropertyHolds6884(t *testing.T) {
	var buf bytes.Buffer
	noteFloorNoLongerTripwires(&buf, 65825)

	if got := buf.String(); got != "" {
		t.Fatalf("the floor still fires before one structural change (65,825 < %d) and the "+
			"build emitted a drift note anyway: %s",
			dataplane.UserspaceShimStructuralChangeInsns, got)
	}
}

// TestFloorSelfCheckBoundary6884 pins the comparison at the exact edge.
//
// The check is `slack < cost -> silent`, so a slack of EXACTLY the
// structural-change cost means one change fits precisely and the property has
// broken. `<=` there would stay silent at the moment it first fails — the
// off-by-one that makes a tripwire fire one change too late, which is the
// entire defect this issue documents, reproduced in the detector for it.
func TestFloorSelfCheckBoundary6884(t *testing.T) {
	cost := dataplane.UserspaceShimStructuralChangeInsns

	var atCost bytes.Buffer
	noteFloorNoLongerTripwires(&atCost, cost)
	if atCost.String() == "" {
		t.Fatalf("slack of exactly %d insns fits one structural change precisely, so the "+
			"property has broken — the note must fire", cost)
	}

	var justUnder bytes.Buffer
	noteFloorNoLongerTripwires(&justUnder, cost-1)
	if justUnder.String() != "" {
		t.Fatalf("slack of %d is one insn short of a structural change, so the property "+
			"still holds — the note must be silent: %s", cost-1, justUnder.String())
	}
}

// TestFloorSelfCheckIsWiredIntoThePassPath6884 binds the WIRING.
//
// noteFloorNoLongerTripwires is inert unless run() calls it on the PASS path.
// Deleting that one call leaves every cell above green while the build goes
// back to saying nothing — which is precisely the silence this whole issue is
// about.
//
// Driven with a stats value whose slack at the REAL floor exceeds the
// structural-change cost, so the note is expected on stderr.
func TestFloorSelfCheckIsWiredIntoThePassPath6884(t *testing.T) {
	// Headroom well above the floor (so this PASSES), but slack large enough
	// that the property has broken. At a 15% floor, 700,000 used leaves 150,000
	// of slack — above the 87,000 cost.
	stats := dataplane.ShimVerifierStats{ProcessedInsns: 700000, InsnLimit: 1000000}
	if stats.HeadroomPct() < dataplane.UserspaceShimMinVerifierHeadroomPct {
		t.Skipf("fixture no longer passes the floor (%.2f%% < %.1f%%); pick a smaller object",
			stats.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	}
	if stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct) <
		dataplane.UserspaceShimStructuralChangeInsns {
		t.Skipf("fixture no longer breaks the property; pick a smaller object")
	}

	var stdout, stderr bytes.Buffer
	exit := run([]string{"shimverify", "/tmp/candidate.o"}, &stdout, &stderr,
		func(string) string { return "" },
		func(string) (dataplane.ShimVerifierStats, error) { return stats, nil })

	if exit != 0 || !strings.HasPrefix(stdout.String(), "PASS ") {
		t.Fatalf("expected a PASS; exit=%d stdout=%q", exit, stdout.String())
	}
	if !strings.Contains(stderr.String(), "#6884") {
		t.Fatalf("run() did not emit the floor drift note on a PASSING build whose floor "+
			"admits %d insns — the check is not wired into the PASS path.\nstderr: %s",
			stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct),
			stderr.String())
	}
}
