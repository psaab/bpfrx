package daemon

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// rss_shutdown_restore_7619_test.go — #7619.
//
// restoreStep0TunablesOnShutdown reverted coalescence, the host-scope knobs and
// neigh retrans_time_ms on daemon stop — but NOT the RSS indirection table
// recorded in priorHostTunables.rssOwned. A NIC whose table xpf concentrated
// onto the userspace-dp queue set kept it after xpfd stopped, so the kernel
// stack ran on a table shaped for a dataplane that was no longer there, until
// the next boot re-applied or an operator ran `ethtool -X <if> default`.
//
// #6801 (PR #7607) fixed the allowlist-SHRINK trigger and deliberately left the
// stop trigger out; this is the tracking number that deferral owed.
//
// THREE POINTS THE ISSUE ASKS TO SETTLE, AND WHERE THEY ARE SETTLED:
//
//   - Bounded work: rssShutdownRestoreBudget, mirroring hostAuthCloseoutBudget
//     (#5874). Pinned by TestBudgetTruncatesRatherThanHangs7619.
//   - Restore on a restart's stop too: systemd delivers an ordinary SIGTERM for
//     both and exposes nothing separating them at stop time, so "exempt a
//     restart" is not implementable. Restore-always is the only choice left,
//     and the churn is two ethtool calls per NIC while not forwarding.
//   - Retry debt: a failure is logged and left. The process is exiting and the
//     ownership map goes with it; the next boot's claim reconciles.

// delayedRSSExec7619 embeds the package's own fakeRSSExecutor and adds only a
// per-call delay, so the budget cell can exercise truncation without a second
// copy of the fake's behaviour.
type delayedRSSExec7619 struct {
	*fakeRSSExecutor
	delay time.Duration
}

func (d *delayedRSSExec7619) runEthtool(args ...string) ([]byte, error) {
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	return d.fakeRSSExecutor.runEthtool(args...)
}

// restoredIfaces7619 extracts the interfaces an `ethtool -X <iface> default`
// was actually issued for, from the fake's recorded argv list.
func restoredIfaces7619(f *fakeRSSExecutor) []string {
	var out []string
	for _, argv := range f.calls {
		if len(argv) >= 3 && argv[0] == "-X" && argv[2] == "default" {
			out = append(out, argv[1])
		}
	}
	sort.Strings(out)
	return out
}

func priorWithRSS7619(ifaces ...string) *priorHostTunables {
	p := &priorHostTunables{rssOwned: map[string]struct{}{}}
	for _, i := range ifaces {
		p.rssOwned[i] = struct{}{}
	}
	return p
}

// THE DEFECT: an owned NIC must have its default table restored on stop.
func TestOwnedRSSIsRestoredOnShutdown7619(t *testing.T) {
	ex := &fakeRSSExecutor{}
	restoreOwnedRSSOnShutdown(priorWithRSS7619("ge-0-0-1", "ge-0-0-2"), ex, time.Minute)

	got := restoredIfaces7619(ex)
	if strings.Join(got, ",") != "ge-0-0-1,ge-0-0-2" {
		t.Errorf("restored %v, want both owned NICs. A NIC left concentrated after xpfd "+
			"stops leaves the kernel stack on a table shaped for a dataplane that is not "+
			"there (#7619)", got)
	}
}

// A FAILURE on one NIC must not abandon the others. A stop has no later tick,
// so anything skipped here is skipped until the next boot.
func TestOneFailureDoesNotAbandonTheRest7619(t *testing.T) {
	ex := &fakeRSSExecutor{argvErr: map[string]argvErrSpec{
		"-X ge-0-0-1 default": {err: fmt.Errorf("simulated ethtool failure")},
	}}
	restoreOwnedRSSOnShutdown(priorWithRSS7619("ge-0-0-1", "ge-0-0-2", "ge-0-0-3"), ex, time.Minute)

	got := restoredIfaces7619(ex)
	if strings.Join(got, ",") != "ge-0-0-1,ge-0-0-2,ge-0-0-3" {
		t.Errorf("restored %v; a failure on one NIC must not stop the others — there is no "+
			"later tick to retry on (#7619)", got)
	}
}

// THE BUDGET TRUNCATES RATHER THAN HANGS. This path runs under the unit's
// TimeoutStopSec=20; a hung ethtool must cost a logged timeout, not a
// SIGKILLed daemon.
func TestBudgetTruncatesRatherThanHangs7619(t *testing.T) {
	inner := &fakeRSSExecutor{}
	ex := &delayedRSSExec7619{fakeRSSExecutor: inner, delay: 40 * time.Millisecond}
	start := time.Now()
	restoreOwnedRSSOnShutdown(
		priorWithRSS7619("a", "b", "c", "d", "e", "f", "g", "h"), ex, 60*time.Millisecond)
	elapsed := time.Since(start)

	if len(restoredIfaces7619(inner)) == 8 {
		t.Error("every NIC was restored despite a budget shorter than the work; the budget " +
			"is not bounding anything")
	}
	if len(restoredIfaces7619(inner)) == 0 {
		t.Error("no NIC was restored at all: the budget must truncate the walk, not skip it")
	}
	// Generous ceiling — this asserts BOUNDEDNESS, not a timing figure. A tight
	// bound here would just move the wall-clock sample.
	if elapsed > 2*time.Second {
		t.Errorf("the restore ran %v against a %v budget; it is not truncating",
			elapsed, 60*time.Millisecond)
	}
}

// EMPTY OWNERSHIP is a no-op, not an error.
func TestNoOwnedNICsIsANoOp7619(t *testing.T) {
	ex := &fakeRSSExecutor{}
	restoreOwnedRSSOnShutdown(&priorHostTunables{}, ex, time.Minute)
	restoreOwnedRSSOnShutdown(nil, ex, time.Minute)
	if got := restoredIfaces7619(ex); len(got) != 0 {
		t.Errorf("restored %v with no ownership recorded; the restore must not escape the "+
			"userspace-dp binding scope", got)
	}
}

// THE EARLY-RETURN TRAP. A NIC with ONLY rss ownership — no host-scope opt-in,
// no coalescence capture, no neigh retrans — must not take the empty-captures
// early return, or this defect survives its own fix: the restore call sits at
// the bottom of restoreStep0TunablesOnShutdown and the guard above it returns
// first.
//
// The table's MIDDLE rows are the ones that do work. rss-only must admit
// (that is #7619); all-empty must skip (or the guard is gone, not fixed); and
// governors-with-active-false must skip, which is what proves the extraction
// did not quietly drop the `active` gate while widening the predicate.
func TestRSSOnlyOwnershipIsNotTreatedAsEmptyCaptures7619(t *testing.T) {
	rssOnly := &priorHostTunables{rssOwned: map[string]struct{}{"ge-0-0-1": {}}}
	cases := []struct {
		name   string
		prior  *priorHostTunables
		active bool
		want   bool
		why    string
	}{
		{"rss-only", rssOnly, false, true,
			"a NIC with only RSS ownership takes the empty-captures early return and is " +
				"never restored (#7619)"},
		{"rss-only-active", rssOnly, true, true,
			"RSS ownership must admit regardless of the host-scope opt-in; the RSS claim " +
				"is not gated on claim-host-tunables"},
		{"nothing", &priorHostTunables{}, true, false,
			"an empty capture set must still skip; a guard that admits everything is " +
				"deleted, not fixed"},
		{"nil", nil, true, false, "a nil snapshot must skip"},
		{"governors-inactive", &priorHostTunables{governors: map[string]string{"cpu0": "powersave"}},
			false, false,
			"host-scope captures are gated on `active` — applyStep0TunablesWith already " +
				"restored them when the opt-in was flipped off at runtime"},
		{"governors-active", &priorHostTunables{governors: map[string]string{"cpu0": "powersave"}},
			true, true, "host-scope captures admit when the opt-in is still active"},
		{"coalesce-only", &priorHostTunables{mlx5Adaptive: map[string]mlx5CoalesceState{"ge-0-0-1": {}}},
			false, true, "coalescence captures admit independently of the opt-in"},
		{"neigh-only", &priorHostTunables{neighRetrans: map[string]string{"ge-0-0-1": "1000"}},
			false, true, "neigh retrans captures admit independently of the opt-in (#1636)"},
	}
	for _, tc := range cases {
		if got := step0RestoreHasCaptures(tc.prior, tc.active); got != tc.want {
			t.Errorf("%s: step0RestoreHasCaptures = %v, want %v: %s",
				tc.name, got, tc.want, tc.why)
		}
	}
}

// THE WIRING. The cells above all call restoreOwnedRSSOnShutdown directly, so
// every one of them stays green if the CALL from restoreStep0Captures is
// deleted — which is precisely the shape of the defect (#7619 is a missing
// call, not a broken function). This cell exercises the shutdown restore from
// its own entry point and asserts the ethtool default actually reached the
// owned NIC.
//
// It is deliberately fed an rss-ONLY snapshot: that routes through the
// empty-captures guard as well, so a fix that adds the call but leaves the
// guard unaware of rssOwned reds here too.
func TestShutdownRestorePathActuallyIssuesTheRSSDefault7619(t *testing.T) {
	ex := &fakeRSSExecutor{}
	restoreStep0Captures(priorWithRSS7619("ge-0-0-1", "ge-0-0-2"), false, &fakeHostFS{}, ex)

	got := restoredIfaces7619(ex)
	if strings.Join(got, ",") != "ge-0-0-1,ge-0-0-2" {
		t.Errorf("the shutdown restore path issued `ethtool -X ... default` for %v, want "+
			"both owned NICs. On stop, xpf leaves the RSS indirection table concentrated "+
			"onto the userspace-dp queue set and the kernel stack runs on it until the "+
			"next boot or a manual `ethtool -X <if> default` (#7619)", got)
	}

	// Control: with nothing owned, this path must issue no ethtool at all —
	// otherwise the cell above would pass on a restore that ignores the map.
	empty := &fakeRSSExecutor{}
	restoreStep0Captures(&priorHostTunables{}, false, &fakeHostFS{}, empty)
	if got := restoredIfaces7619(empty); len(got) != 0 {
		t.Errorf("restored %v from an empty snapshot", got)
	}
}
