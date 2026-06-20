package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #2114 regression tests for the NAT pool-alarm monitor's lifecycle vs the
// daemon's d.dp / bootstrap-exit transitions. These MUST be run under
// `go test -race`; the bug they guard is a data race on the unsynchronized
// d.dp interface field (sampler read vs bootstrap-exit d.dp=nil write) and a
// second race on the d.natPoolAlarm pointer itself (now atomic.Pointer) that
// the runtime start/discard introduced and the show-security-alarms reader
// raced.
//
// The tests target the REAL production gating helpers (maybeStartNATPoolAlarm,
// stopAndDiscardNATPoolAlarm, natPoolAlarms) rather than a hand-rolled racy
// field, so they are genuine fail-pre / pass-post regression guards:
//   - TestNATPoolAlarm_BootGate fails if the boot-time start drops its
//     !inBootstrap() gate (Edit 1): a sampler goroutine then reads d.dp while
//     the test writes d.dp = nil.
//   - TestNATPoolAlarm_RollbackDiscard fails if enterBootstrapMode drops the
//     stop+discard (Edit 3): a stale sampler survives the rollback and races
//     a later d.dp = nil re-arm-failure write.
//   - TestNATPoolAlarm_PointerPublication fails if d.natPoolAlarm reverts to a
//     plain pointer (Edit 0): the show-security-alarms reader races the
//     runtime start/discard writes.

// newNATPoolAlarmTestDaemon builds a minimal *Daemon with a non-nil runtime
// dataplane fake (so d.dp != nil) and an injected apply-body seam (so
// enterBootstrapMode skips the real fs/FRR/dataplane teardown but still runs
// the #2114 stop+discard placed before that seam return).
func newNATPoolAlarmTestDaemon() *Daemon {
	d := &Daemon{}
	d.dp = &runtimeOnlyApplyTestDP{}
	d.applyBodyForTest = func(_ *config.Config) {}
	// Fast sampler cadence so any monitor that DOES start actively reads
	// d.dp during the concurrent d.dp-write loops below — making the
	// sampler-vs-d.dp race detectable under -race if a gate/discard is
	// removed (not merely caught by the start/discard assertions).
	d.natPoolAlarmTestTick = time.Millisecond
	return d
}

// writeDPFor mirrors the bootstrap-exit/re-arm-failure write of the daemon's
// d.dp field in a tight loop for the given duration, then joins. It is the
// concurrent writer the monitor's sampler would race if a start gate or the
// rollback discard were removed.
func writeDPFor(dur time.Duration, d *Daemon) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(dur)
		for time.Now().Before(deadline) {
			d.dp = nil
			d.dp = &runtimeOnlyApplyTestDP{}
		}
	}()
	wg.Wait()
}

// TestNATPoolAlarm_BootGate verifies that the production start helper does NOT
// launch a sampler goroutine while in bootstrap mode, so the bootstrap-exit
// d.dp = nil write cannot race a sampler read. With the gate removed, a
// sampler goroutine started here reads d.dp on its fast tick while the writer
// nils d.dp → -race trips.
func TestNATPoolAlarm_BootGate(t *testing.T) {
	d := newNATPoolAlarmTestDaemon()
	d.bootstrapMode.Store(true)

	// In bootstrap mode the start is gated off: no monitor, no sampler.
	d.maybeStartNATPoolAlarm()
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("monitor must NOT start in bootstrap mode (Edit 1 gate)")
	}

	// Mirror the bootstrap-exit failure write of d.dp, run long enough to
	// overlap several 1ms sampler ticks. Because the gate suppressed the
	// start, no sampler goroutine exists, so this cannot race. If the gate
	// were removed, a sampler on the 1ms tick would be reading d.dp here and
	// -race would trip.
	writeDPFor(50*time.Millisecond, d)
	d.stopAndDiscardNATPoolAlarm()

	// Out of bootstrap, the gate passes and the monitor starts.
	d.bootstrapMode.Store(false)
	d.maybeStartNATPoolAlarm()
	if d.natPoolAlarm.Load() == nil {
		t.Fatal("monitor MUST start once out of bootstrap with d.dp armed")
	}
	d.stopAndDiscardNATPoolAlarm()
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("stopAndDiscard must clear the pointer")
	}
}

// TestNATPoolAlarm_RollbackDiscard verifies the rollback path stops AND
// discards the monitor so a later re-arm-failure d.dp = nil write cannot race
// a stale sampler goroutine, and a corrected re-arm builds a FRESH monitor
// (the Monitor is not restartable after Stop).
func TestNATPoolAlarm_RollbackDiscard(t *testing.T) {
	d := newNATPoolAlarmTestDaemon()

	// Simulate a successful bootstrap-exit arm: out of bootstrap, monitor
	// running on the fast (1ms) test tick so it actively samples d.dp.
	d.bootstrapMode.Store(false)
	d.maybeStartNATPoolAlarm()
	first := d.natPoolAlarm.Load()
	if first == nil {
		t.Fatal("monitor must start on a successful arm")
	}

	// Roll back to bootstrap. enterBootstrapMode must Stop()+discard the
	// monitor (Stop joins the sampler goroutine) before returning at the
	// applyBodyForTest seam.
	d.enterBootstrapMode()
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("enterBootstrapMode must stop+discard the monitor (Edit 3)")
	}
	if !d.inBootstrap() {
		t.Fatal("enterBootstrapMode must re-enter bootstrap mode")
	}

	// A re-arm attempt while STILL in bootstrap must stay gated off.
	d.maybeStartNATPoolAlarm()
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("monitor must remain gated off while in bootstrap after rollback")
	}

	// The re-arm-failure write of d.dp, run long enough to overlap several
	// 1ms sampler ticks: no sampler survives the rollback, so this cannot
	// race. If the discard were missing, the first monitor's sampler would
	// be reading d.dp here and -race would trip (in addition to the discard
	// assertion above).
	writeDPFor(50*time.Millisecond, d)

	// A corrected commit re-arms: clear bootstrap (as exitBootstrapMode does
	// before runBootstrapExitStartup), then start — a FRESH monitor.
	d.bootstrapMode.Store(false)
	d.maybeStartNATPoolAlarm()
	second := d.natPoolAlarm.Load()
	if second == nil {
		t.Fatal("a corrected re-arm must build a fresh monitor")
	}
	if second == first {
		t.Fatal("re-arm must build a NEW monitor (Monitor is not restartable)")
	}
	d.stopAndDiscardNATPoolAlarm()
}

// TestNATPoolAlarm_PointerPublication hammers natPoolAlarms() (the
// show-security-alarms reader) concurrently with the runtime start/discard of
// the monitor pointer. With d.natPoolAlarm as atomic.Pointer the reads/writes
// of the pointer are race-free; as a plain field they are not. This is the
// deterministic guard for Edit 0.
func TestNATPoolAlarm_PointerPublication(t *testing.T) {
	d := newNATPoolAlarmTestDaemon()
	d.bootstrapMode.Store(false)

	var readers sync.WaitGroup
	stop := make(chan struct{})

	// Readers: the gRPC/CLI render path, looping until the writer is done.
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = d.natPoolAlarms()
				}
			}
		}()
	}

	// Writer: runtime start/discard cycles (bootstrap exit / rollback),
	// inline so the readers are guaranteed to overlap a full run before stop.
	for i := 0; i < 2000; i++ {
		d.maybeStartNATPoolAlarm()
		d.stopAndDiscardNATPoolAlarm()
	}

	close(stop)
	readers.Wait()
	d.stopAndDiscardNATPoolAlarm()
}
