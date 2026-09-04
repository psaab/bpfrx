package userspace

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #7675 MAJOR 4: the constraint is about the REACHABLE deadline, not the clamp.
//
// `controlMaxDeadline` is 120s and `TimeoutStopSec` is 20s, so reading the two
// constants gives "6x". That is wrong, and the way it is wrong is worth naming
// because it is a repeatable misreading: `controlMaxDeadline` is a CLAMP on a
// value that cannot occur, not a bound the code can reach.
//
// `controlRoundtripDeadline` is called from exactly one production site
// (`requestDetailedLocked`, process_control.go), and that call is strictly
// AFTER the #2744 pre-flight `return` that rejects a body over
// MaxControlRequestBytes. So the largest body that ever reaches the deadline
// computation is 64 MiB, giving base + 64s = 67s. The clamp at 120s is dead for
// reachability; the test asserting `deadline(1 GiB) == cap` says so itself
// ("cannot occur — the #2744 pre-flight rejects it").
//
// #7675 recorded MAJOR 4 as "6x, not 3.35x" and used the escalation to promote
// it into a leading design constraint. The substance survives — 67s still
// blows a 20s stop budget — but the magnitude was overstated ~1.8x, and one row
// of that issue's fold table inverts: plan v68 folded this finding at "~67s"
// and was graded "FOLDED, ON THE WRONG NUMBER" when 67s is the right number.
//
// The existing #4036 cell asserts `deadline(64 MiB) <= cap`, which passes
// whether or not the cap is reachable. These cells assert the reachable bound.

// unitStopTimeout reads TimeoutStopSec from the shipped unit rather than
// pinning a literal, per the #8233 precedent: a comment stating the
// relationship is true only until someone edits the unit.
func unitStopTimeout(t *testing.T) time.Duration {
	t.Helper()
	const unit = "../../../test/incus/xpfd.service"
	b, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("read %s: %v", unit, err)
	}
	m := regexp.MustCompile(`(?m)^TimeoutStopSec=(\d+)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no TimeoutStopSec in %s — this cell can no longer see the value it "+
			"exists to compare against and would pass vacuously", unit)
	}
	secs, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse TimeoutStopSec %q: %v", m[1], err)
	}
	return time.Duration(secs) * time.Second
}

// The clamp must stay UNREACHABLE, and the assertion is a relationship between
// the request cap and the deadline cap rather than two pinned literals.
//
// This is the cell that reds if someone raises MaxControlRequestBytes: at
// 128 MiB the scaled deadline would be 3+128 = 131s, the clamp would bind, and
// "the cap is unreachable" would silently stop being true.
func TestControlDeadlineCapIsUnreachableOnAdmissibleRequests7675(t *testing.T) {
	worst := controlRoundtripDeadline(MaxControlRequestBytes)

	if worst >= controlMaxDeadline {
		t.Fatalf("the largest ADMISSIBLE request (%d bytes) now scales to %v, which reaches "+
			"the %v clamp. The clamp was dead code for reachability and analyses of the stop "+
			"budget relied on that: the reachable bound was base+64s. Either lower "+
			"MaxControlRequestBytes or re-derive every stop-budget claim against the new "+
			"reachable bound — do NOT just raise the clamp.",
			MaxControlRequestBytes, worst, controlMaxDeadline)
	}

	// The exact reachable worst case, so a change to either term is visible.
	wantWorst := controlBaseDeadline + 64*controlDeadlinePerMiB
	if worst != wantWorst {
		t.Fatalf("reachable worst-case control deadline = %v, want %v "+
			"(base %v + 64 MiB x %v). #7675's MAJOR 4 constraint is stated against this "+
			"number, not against the %v clamp.",
			worst, wantWorst, controlBaseDeadline, controlDeadlinePerMiB, controlMaxDeadline)
	}
}

// THE WIRING, not the function: the bound above holds only because the
// pre-flight rejects an over-cap body BEFORE the deadline is computed. Delete
// that check and a larger body reaches controlRoundtripDeadline, so this cell
// fails on the revert that would make the cell above lie.
//
// No socket is created: with the pre-flight intact the request is refused on
// size before any dial, so a nonexistent socket path is never reached. If the
// pre-flight is removed the call proceeds to net.DialTimeout and fails with a
// connection error instead — a different, distinguishable failure.
func TestOverCapRequestIsRefusedBeforeDial7675(t *testing.T) {
	// 65 x 1 MiB strings: over the 64 MiB cap, and far cheaper to marshal than
	// millions of short CIDR entries.
	const chunk = 1 << 20
	prefixes := make([]string, 65)
	for i := range prefixes {
		prefixes[i] = strings.Repeat("a", chunk)
	}
	req := ControlRequest{
		Type: "apply_snapshot",
		Snapshot: &ConfigSnapshot{
			Version:      ProtocolVersion,
			AddressBooks: []AddressBookSnapshot{{ID: 1, Name: "oversize", PrefixesV6: prefixes}},
		},
	}

	m := New()
	// A path that cannot be dialled. Reaching it at all means the pre-flight
	// did not run.
	m.cfg.ControlSocket = "/nonexistent/xpf-7675/control.sock"

	m.mu.Lock()
	_, err := m.requestDetailedLocked(req)
	m.mu.Unlock()

	if err == nil {
		t.Fatal("an over-cap control request was accepted; the #2744 pre-flight is gone and " +
			"the reachable-deadline bound in this file no longer holds")
	}
	if !strings.Contains(err.Error(), "exceeding the dataplane control-socket limit") {
		t.Fatalf("over-cap request failed with %q, not the pre-flight size refusal. If this is "+
			"a dial error the size check no longer runs BEFORE the dial, so an over-cap body "+
			"now reaches controlRoundtripDeadline and can hit the %v clamp.",
			err, controlMaxDeadline)
	}
}

// MAJOR 4 as a CHECKED constraint rather than a sentence in a plan.
//
// A control round-trip is performed under m.mu (UpdatePolicyScheduleState holds
// it from entry through requestLocked at manager_compile.go). Anything waiting
// on m.mu during shutdown therefore waits up to the round-trip deadline, and
// the unit SIGKILLs at TimeoutStopSec. The assertion is deliberately in the
// direction that is TRUE today — the deadline exceeds the budget — so the cell
// documents a live constraint instead of a wish; it reds if someone "fixes"
// this by editing the unit, which would not fix it.
func TestControlRoundtripBoundExceedsUnitStopBudget7675(t *testing.T) {
	stop := unitStopTimeout(t)
	worst := controlRoundtripDeadline(MaxControlRequestBytes)

	if worst <= stop {
		t.Fatalf("the reachable control round-trip deadline (%v) no longer exceeds the unit's "+
			"TimeoutStopSec (%v). If this became true by RAISING TimeoutStopSec, the hazard is "+
			"unchanged and this cell must be re-derived rather than deleted; if it became true "+
			"by shrinking the deadline, #7675's MAJOR 4 constraint can be retired.",
			worst, stop)
	}

	// Pin the ratio's magnitude so the "6x" misreading cannot come back
	// unnoticed. 67s/20s = 3.35x; the clamp-derived figure was 120s/20s = 6x.
	ratio := float64(worst) / float64(stop)
	if ratio < 3.0 || ratio > 4.0 {
		t.Fatalf("reachable overrun ratio %.2fx (%v deadline vs %v stop budget) left the "+
			"3-4x band. #7675 records this as 3.35x; a value near 6x means the CLAMP is being "+
			"measured instead of the reachable bound.", ratio, worst, stop)
	}
}
