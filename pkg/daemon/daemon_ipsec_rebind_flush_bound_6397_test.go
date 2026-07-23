package daemon

// daemon_ipsec_rebind_flush_bound_6397_test.go — #6397 regression coverage.
//
// stopIPsecRebindLoop cancels + JOINS the DHCP-lease-change rebind retry loop at
// shutdown. The loop's cancel is observed at its ctx.Done / ticker select and at
// applySem.Acquire(ctx, …) — but NOT inside a swanctl apply already in flight:
// tryIPsecRebindRetry's re-render+reload shells out under
// context.WithTimeout(context.Background(), swanctlTimeout=15s) (pkg/ipsec/
// manager.go runSwanctl), a BACKGROUND context the loop's cancel cannot
// interrupt, plus a 5s WaitDelay. So a rebind that is MID-APPLY when shutdown
// fires would block a plain d.ipsecRebindWg.Wait() for up to ~20s.
//
// stopIPsecRebindLoop runs in runShutdownSequence BEFORE the HA takeover fence,
// so before #6397 that unbounded join could delay the fence long enough to blow
// the systemd 20s TimeoutStopSec and get the process SIGKILLed before the peer
// takeover ran — the same fence-starvation class the #6395 aggregator join bound
// fixed. The join is now bounded by ipsecRebindJoinTimeout. These tests prove
// the bound fires when the loop is wedged mid-apply (RED-on-revert: reverting to
// a plain d.ipsecRebindWg.Wait() blocks forever, so the stop never returns and
// the generous in-test timeout trips a clean t.Fatal) and that the happy path —
// a loop that is not wedged — is not penalized by the bound.

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestStopIPsecRebindLoopBoundsStalledMidApply proves stopIPsecRebindLoop RETURNS
// within its bound even when the retry loop is wedged INSIDE the swanctl apply (a
// background-context shell-out the loop's cancel cannot interrupt), so the
// shutdown fence downstream is never starved.
//
// RED-on-revert: replacing the bounded select in stopIPsecRebindLoop with a plain
// `d.ipsecRebindWg.Wait()` makes it block on the parked apply forever, the `done`
// channel never closes, and the generous outer select trips t.Fatal.
func TestStopIPsecRebindLoopBoundsStalledMidApply(t *testing.T) {
	// A wedged swanctl seam: the retry loop's apply parks until the test tears
	// down, modeling a mid-apply swanctl shell-out under context.Background that
	// the loop's ctx cancel does NOT interrupt. `entered` proves the loop genuinely
	// reached the blocking apply while holding applySem (so the bound, not an
	// early ctx-cancel unwind, is what let stopIPsecRebindLoop return).
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{}, 1)
	d, cancel := newIPsecRebindDaemon(t, func(*config.Config) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release // NOT ctx-aware — models the background-context swanctl shell-out
		return errors.New("swanctl --load-all: released at teardown")
	})
	t.Cleanup(cancel)

	// Arm the loop; the fast ticker (ipsecRebindRetryEvery = 2ms) drives the first
	// tick into tryIPsecRebindRetry, which acquires applySem and blocks in the
	// wedged apply.
	d.armIPsecRebind()

	// Wait until the loop is genuinely mid-apply before driving the stop.
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("retry loop never reached the swanctl apply — cannot exercise the " +
			"mid-apply stall the bound guards")
	}

	// Drive stopIPsecRebindLoop off the test goroutine so a reverted (unbounded)
	// join surfaces as a clean timeout rather than hanging the whole suite.
	done := make(chan struct{})
	start := time.Now()
	go func() {
		d.stopIPsecRebindLoop()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		// The bound must have fired: the apply is still wedged (release is only
		// closed in cleanup, after this returns), so a return here can only mean
		// the ipsecRebindJoinTimeout select proceeded past the stalled join.
		if elapsed < ipsecRebindJoinTimeout {
			t.Fatalf("stopIPsecRebindLoop returned in %s, before the %s bound — the "+
				"stalled apply was not actually exercised", elapsed, ipsecRebindJoinTimeout)
		}
	case <-time.After(ipsecRebindJoinTimeout + 5*time.Second):
		t.Fatal("stopIPsecRebindLoop did not return — the retry-loop join is UNBOUNDED; " +
			"a mid-apply swanctl shell-out (background context, up to ~20s) blocks shutdown " +
			"BEFORE the HA takeover fence and can blow the systemd 20s stop budget (#6397)")
	}

	// The stopped latch + cleared cancel must be set exactly as the unbounded
	// path did, so a late armIPsecRebind cannot resurrect the loop after the join.
	d.ipsecRebindMu.Lock()
	stopped := d.ipsecRebindStopped
	cancelCleared := d.ipsecRebindCancel == nil
	d.ipsecRebindMu.Unlock()
	if !stopped {
		t.Error("stopIPsecRebindLoop must latch ipsecRebindStopped even on a bounded (timed-out) join")
	}
	if !cancelCleared {
		t.Error("stopIPsecRebindLoop must clear ipsecRebindCancel even on a bounded join")
	}
}

// TestStopIPsecRebindLoopFastJoinNotPenalized proves the bound does not slow the
// normal case: a loop that is armed but NOT wedged (its apply returns promptly)
// cancels + joins in well under the budget (the select takes the `done` branch,
// not `time.After`). The apply keeps failing fast so the loop stays armed and
// ticking right up to the cancel, exercising the cancel-while-active path.
func TestStopIPsecRebindLoopFastJoinNotPenalized(t *testing.T) {
	d, cancel := newIPsecRebindDaemon(t, func(*config.Config) error {
		return errors.New("swanctl --load-all: charon down") // returns immediately
	})
	t.Cleanup(cancel)

	d.armIPsecRebind()
	// Give the loop a moment to be running/ticking before we stop it.
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	start := time.Now()
	go func() {
		d.stopIPsecRebindLoop()
		close(done)
	}()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed >= ipsecRebindJoinTimeout {
			t.Fatalf("stopIPsecRebindLoop took %s for an unwedged loop — the bound must "+
				"not delay the happy path (budget %s)", elapsed, ipsecRebindJoinTimeout)
		}
	case <-time.After(ipsecRebindJoinTimeout):
		t.Fatal("stopIPsecRebindLoop did not join an unwedged (fast-apply) loop before the bound")
	}
}
