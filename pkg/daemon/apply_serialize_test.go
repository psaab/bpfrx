// #846: Serialization contract for the apply semaphore.
//
// applyConfig + commitAndApply + commitConfirmedAndApply all share
// d.applySem so that two concurrent callers can never interleave
// across VRF/tunnel/FRR-reload steps and so the commit→apply pair
// is atomic per caller. These tests exercise the public API
// (applyConfig directly; commit*AndApply via context-respecting
// Acquire) and would fail if a future refactor:
//
//   - Removed Acquire from applyConfig (TestApplyConfigSerializes
//     would see >1 concurrent body invocation).
//   - Removed Acquire from commitAndApply / commitConfirmedAndApply,
//     or moved Commit() before Acquire (the held-semaphore test
//     would not see a context.DeadlineExceeded — instead the call
//     would panic on the nil store).
package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// applyConfig must serialize concurrent callers via d.applySem.
// Uses applyBodyForTest as a seam so the body of applyConfigLocked
// (which would otherwise touch d.dp / d.routing / d.frr) is replaced
// with a counter that records the maximum concurrent invocations.
func TestApplyConfigSerializes(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	var (
		inFlight int32
		maxSeen  int32
	)
	d.applyBodyForTest = func(_ *config.Config) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			cur := atomic.LoadInt32(&maxSeen)
			if n <= cur || atomic.CompareAndSwapInt32(&maxSeen, cur, n) {
				break
			}
		}
		// Hold long enough that any missing serialization would
		// be visible as inFlight > 1.
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
	}

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			d.applyConfig(nil)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("applyConfig must serialize via applySem; saw %d concurrent body invocations", got)
	}
}

// commitAndApply must Acquire the semaphore BEFORE calling
// store.Commit. We hold the semaphore externally and run
// commitAndApply with a tight deadline; the expected outcome is
// context.DeadlineExceeded (proves Acquire blocked). If a future
// refactor moved Commit() before Acquire, the call would either
// panic on the nil store or succeed without ctx.Err.
func TestCommitAndApplyRespectsSemaphore(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("setup acquire: %v", err)
	}
	defer d.applySem.Release(1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := d.commitAndApply(ctx, "", false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("commitAndApply must surface ctx err while semaphore is held; got %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := d.commitConfirmedAndApply(ctx2, 1, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("commitConfirmedAndApply must surface ctx err while semaphore is held; got %v", err)
	}
}
