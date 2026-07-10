package natpoolalarm

import (
	"sync"
	"testing"
	"time"
)

// TestConcurrentStopNoDoubleClosePanic pins #4909: two goroutines racing
// Monitor.Stop must not panic. The pre-fix Stop used a select/default guard
// around close(m.stop), which is NOT atomic — both callers could observe the
// channel open, both fall to default, and both close it, panicking on the
// second close. A sync.Once serializes the close.
//
// RED on revert: restore the select/default close and this test panics
// ("close of closed channel") under the concurrent drivers below, especially
// with -race.
func TestConcurrentStopNoDoubleClosePanic(t *testing.T) {
	for _, started := range []bool{false, true} {
		m := New(func() View { return View{} }, nil)
		if started {
			// A long tick so run() blocks in select rather than evaluating; Stop
			// still closes m.stop and joins the goroutine.
			m.SetTickForTest(time.Hour)
			m.Start()
		}

		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Stop()
			}()
		}
		wg.Wait()

		// A further Stop after the racers is still safe (idempotent).
		m.Stop()
	}
}
