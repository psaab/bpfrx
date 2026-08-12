package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #2114 regression tests for the NAT pool-alarm monitor's lifecycle vs the
// daemon's dataplane-cell / bootstrap-exit transitions. These MUST be run
// under `go test -race`. The original bug was a data race on the
// unsynchronized d.dp interface field (sampler read vs bootstrap-exit
// d.dp=nil write); the field is now the dpCell atomic.Pointer
// (dataplane()/setDataplane()), and writeDPFor publishes through
// setDataplane, so these tests pin the lifecycle gates (bootstrap start
// gate, rollback stop+discard, pointer publication) against the REAL
// concurrent writer. The second race these cover is on the d.natPoolAlarm
// pointer itself (atomic.Pointer) that the runtime start/discard introduced
// and the show-security-alarms reader raced.
//
// The tests target the REAL production gating helpers (maybeStartNATPoolAlarm,
// stopAndDiscardNATPoolAlarm, natPoolAlarms) rather than a hand-rolled racy
// field, so they are genuine fail-pre / pass-post regression guards:
//   - TestNATPoolAlarm_BootGate fails if the boot-time start drops its
//     !inBootstrap() gate (Edit 1): a sampler goroutine then reads the
//     dataplane cell while the test clears it.
//   - TestNATPoolAlarm_RollbackDiscard fails if enterBootstrapMode drops the
//     stop+discard (Edit 3): a stale sampler survives the rollback and races
//     a later re-arm-failure clear.
//   - TestNATPoolAlarm_PointerPublication fails if d.natPoolAlarm reverts to a
//     plain pointer (Edit 0): the show-security-alarms reader races the
//     runtime start/discard writes.

// newNATPoolAlarmTestDaemon builds a minimal *Daemon with a non-nil runtime
// dataplane fake published in the cell (so d.dataplane() != nil) and an
// injected apply-body seam (so
// enterBootstrapMode skips the real fs/FRR/dataplane teardown but still runs
// the #2114 stop+discard placed before that seam return).
func newNATPoolAlarmTestDaemon() *Daemon {
	d := &Daemon{}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	d.applyBodyForTest = func(_ *config.Config) {}
	// Fast sampler cadence so any monitor that DOES start actively reads
	// the dataplane cell during the concurrent write loops below — making any
	// residual sampler-vs-publication race detectable under -race if a gate/discard is
	// removed (not merely caught by the start/discard assertions).
	d.natPoolAlarmTestTick = time.Millisecond
	return d
}

// writeDPFor mirrors the bootstrap-exit/re-arm-failure publication of the
// daemon's dataplane cell in a tight loop for the given duration, then joins.
// It is the concurrent writer the monitor's sampler would race if a start
// gate or the rollback discard were removed.
func writeDPFor(dur time.Duration, d *Daemon) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(dur)
		for time.Now().Before(deadline) {
			d.setDataplane(nil)
			d.setDataplane(&runtimeOnlyApplyTestDP{})
		}
	}()
	wg.Wait()
}

// TestNATPoolAlarm_BootGate verifies that the production start helper does NOT
// launch a sampler goroutine while in bootstrap mode, so the bootstrap-exit
// cell clear cannot race a sampler read. With the gate removed, a
// sampler goroutine started here reads the cell on its fast tick while the
// writer clears it.
func TestNATPoolAlarm_BootGate(t *testing.T) {
	d := newNATPoolAlarmTestDaemon()
	d.bootstrapMode.Store(true)

	// In bootstrap mode the start is gated off: no monitor, no sampler.
	d.maybeStartNATPoolAlarm()
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("monitor must NOT start in bootstrap mode (Edit 1 gate)")
	}

	// Mirror the bootstrap-exit failure clear, run long enough to
	// overlap several 1ms sampler ticks. Because the gate suppressed the
	// start, no sampler goroutine exists, so this cannot race. If the gate
	// were removed, a sampler on the 1ms tick would be reading the cell here.
	writeDPFor(50*time.Millisecond, d)
	d.stopAndDiscardNATPoolAlarm()

	// Out of bootstrap, the gate passes and the monitor starts.
	d.bootstrapMode.Store(false)
	d.maybeStartNATPoolAlarm()
	if d.natPoolAlarm.Load() == nil {
		t.Fatal("monitor MUST start once out of bootstrap with the dataplane armed")
	}
	d.stopAndDiscardNATPoolAlarm()
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("stopAndDiscard must clear the pointer")
	}
}

// TestNATPoolAlarm_RollbackDiscard verifies the rollback path stops AND
// discards the monitor so a later re-arm-failure cell clear cannot race
// a stale sampler goroutine, and a corrected re-arm builds a FRESH monitor
// (the Monitor is not restartable after Stop).
func TestNATPoolAlarm_RollbackDiscard(t *testing.T) {
	d := newNATPoolAlarmTestDaemon()

	// Simulate a successful bootstrap-exit arm: out of bootstrap, monitor
	// running on the fast (1ms) test tick so it actively samples the cell.
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

	// The re-arm-failure cell clear, run long enough to overlap several
	// 1ms sampler ticks: no sampler survives the rollback, so this cannot
	// race. If the discard were missing, the first monitor's sampler would
	// be reading the cell here (in addition to the discard
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
//
// Codex PR #6743 r6-F6: the overlap used to rest on the comment
// "inline so the readers are guaranteed to overlap" — which the code did
// not establish. Nothing ordered a reader against the writer, so a
// schedule in which no reader ran until after the 2000 write cycles
// completed was legal and the test would pass having exercised nothing.
// Two rendezvous now make it a property of the test: `ready` proves every
// reader made a pass BEFORE the first write, and `overlap` proves every
// reader completed a pass that BEGAN after the write loop started, with
// the writer looping until that holds.
func TestNATPoolAlarm_PointerPublication(t *testing.T) {
	d := newNATPoolAlarmTestDaemon()
	d.bootstrapMode.Store(false)

	const numReaders = 4
	var readers sync.WaitGroup
	var firstPass, overlapPass sync.WaitGroup
	firstPass.Add(numReaders)
	overlapPass.Add(numReaders)
	stop := make(chan struct{})
	writing := make(chan struct{})
	ready := make(chan struct{})
	overlap := make(chan struct{})

	// Readers: the gRPC/CLI render path, looping until the writer is done.
	for r := 0; r < numReaders; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			_ = d.natPoolAlarms()
			firstPass.Done()
			credited := false
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Sample the writer's announcement BEFORE the pass, so a
				// credited pass provably began after the writes started.
				started := false
				select {
				case <-writing:
					started = true
				default:
				}
				_ = d.natPoolAlarms()
				if started && !credited {
					credited = true
					overlapPass.Done()
				}
			}
		}()
	}
	go func() { firstPass.Wait(); close(ready) }()
	go func() { overlapPass.Wait(); close(overlap) }()

	<-ready // every reader has touched the pointer before any write

	// Writer: runtime start/discard cycles (bootstrap exit / rollback).
	close(writing)
	overlapped := false
	hard := time.Now().Add(30 * time.Second)
	for i := 0; i < 2000 || !overlapped; i++ {
		d.maybeStartNATPoolAlarm()
		d.stopAndDiscardNATPoolAlarm()
		if !overlapped {
			select {
			case <-overlap:
				overlapped = true
			default:
			}
			if !overlapped && time.Now().After(hard) {
				t.Fatal("no reader completed a pass inside the write loop: the reader/writer " +
					"overlap this test claims to exercise did not happen")
			}
		}
	}

	close(stop)
	readers.Wait()
	d.stopAndDiscardNATPoolAlarm()
}
