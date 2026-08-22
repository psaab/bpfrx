package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #7532: d.vipWarnedIfaces was reset on the apply path (under applySem) and
// lazily created / read / assigned / deleted on the VRRP reconcile path, which
// holds no such lock. The two used unrelated synchronization.
//
// A reset landing between the reconcile path's nil-check and its assignment is
// `assignment to entry in nil map`; two reconcile writers are a fatal
// `concurrent map writes` throw. The impact is the daemon crashing.
//
// These run under `go test -race`. Without -race the pre-fix code still panics
// often enough for the loop below to catch it, but -race is what makes it
// deterministic — so the probe reports its own iteration counts rather than
// asserting a fixed ratio.

// TestVIPWarningSuppressionIsRaceFree7532 is the defect proper.
//
// The two goroutines run for a fixed WALL-CLOCK window rather than a fixed
// iteration count each. Equal counts would be a false green: the reset is a
// one-line store and the warn path allocates a map, so the cheap side finishes
// inside the expensive side's first passes and they never interleave where it
// matters. Both counts are reported and both must be non-trivial.
func TestVIPWarningSuppressionIsRaceFree7532(t *testing.T) {
	d := &Daemon{}
	var resets, warns int64
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { // the apply path
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			d.resetVIPWarnings()
			atomic.AddInt64(&resets, 1)
		}
	}()

	wg.Add(1)
	go func() { // the VRRP reconcile path
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if d.shouldWarnVIPIface("reth0") {
				atomic.AddInt64(&warns, 1)
			}
			d.clearVIPWarning("reth1")
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	r, w := atomic.LoadInt64(&resets), atomic.LoadInt64(&warns)
	t.Logf("resets=%d warns=%d", r, w)
	if r < 100 || w < 10 {
		t.Fatalf("the probe did not exercise the interleaving (resets=%d warns=%d): a green "+
			"run here would prove nothing", r, w)
	}
}

// TestVIPWarningSuppressesRepeats7532 is the TIGHTENING control.
//
// A "fix" that made shouldWarnVIPIface always return true would be race-free and
// would pass the probe above, while destroying the log-spam suppression the set
// exists for — the reconcile ticker calls this every pass. This pins the other
// side, and it pins the check-and-record as ONE critical section: the open-coded
// version tested and set separately, so two passes could both observe "not yet
// warned" and both log.
func TestVIPWarningSuppressesRepeats7532(t *testing.T) {
	d := &Daemon{}

	if !d.shouldWarnVIPIface("reth0") {
		t.Fatal("the FIRST occurrence must warn")
	}
	for i := 0; i < 50; i++ {
		if d.shouldWarnVIPIface("reth0") {
			t.Fatalf("occurrence %d warned again: the reconcile ticker would spam this line "+
				"every pass, which is exactly what the suppression set exists to prevent", i+2)
		}
	}

	// A different interface is tracked independently.
	if !d.shouldWarnVIPIface("reth1") {
		t.Error("a DIFFERENT interface must warn on its first occurrence — the suppression is " +
			"per-interface, not global")
	}

	// Reappearing clears suppression, so a later disappearance warns again.
	d.clearVIPWarning("reth0")
	if !d.shouldWarnVIPIface("reth0") {
		t.Error("after the interface reappeared and its suppression was cleared, a later " +
			"disappearance must warn again")
	}

	// A config commit resets everything.
	d.resetVIPWarnings()
	if !d.shouldWarnVIPIface("reth1") {
		t.Error("a config commit must reset suppression so the new config gets fresh warnings")
	}
}

// TestVIPWarningAccessorsSurviveANilMap7532 pins the nil-map path directly: the
// zero-value Daemon has no map, and every accessor must cope. Before #7532 the
// reset set the field to nil while the reconcile path assumed it could assign
// after its own nil-check — this asserts each entry point independently rather
// than relying on the race probe to happen to hit the window.
func TestVIPWarningAccessorsSurviveANilMap7532(t *testing.T) {
	t.Run("clear on a nil map", func(t *testing.T) {
		d := &Daemon{}
		d.clearVIPWarning("reth0") // must not panic
	})
	t.Run("reset on a nil map", func(t *testing.T) {
		d := &Daemon{}
		d.resetVIPWarnings()
		d.resetVIPWarnings()
	})
	t.Run("warn after a reset", func(t *testing.T) {
		d := &Daemon{}
		if !d.shouldWarnVIPIface("reth0") {
			t.Fatal("first warn")
		}
		d.resetVIPWarnings()
		if !d.shouldWarnVIPIface("reth0") {
			t.Error("assignment after a reset must re-create the map, not panic on a nil one")
		}
	})
}

// TestApplyResetsVIPWarnings7532 binds the WIRING, not the accessor.
//
// The three tests above drive resetVIPWarnings / shouldWarnVIPIface directly, so
// they pass whether or not the apply path still calls the reset — deleting the
// call site leaves every one of them green. This drives the production entry
// point (applyConfigLocked with the apply body stubbed) and asserts the
// suppression was actually cleared, which is the property "reset on config
// commit" names.
func TestApplyResetsVIPWarnings7532(t *testing.T) {
	d := &Daemon{}
	d.applyBodyForTest = func(*config.Config) {}

	if !d.shouldWarnVIPIface("reth0") {
		t.Fatal("setup: the first occurrence must warn")
	}
	if d.shouldWarnVIPIface("reth0") {
		t.Fatal("setup: the second occurrence must be suppressed — otherwise the assertion " +
			"below cannot tell a reset from no suppression at all")
	}

	if err := d.applyConfigLocked(context.Background(), &config.Config{}); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	if !d.shouldWarnVIPIface("reth0") {
		t.Error("a config apply did NOT reset the VIP warning suppression: an interface that " +
			"warned under the previous config stays silent under the new one, so an operator " +
			"who fixes a config and re-commits never learns the interface is still missing")
	}
}
