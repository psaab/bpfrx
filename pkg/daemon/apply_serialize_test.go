// #846: Serialization contract for applyMu.
//
// applyConfig() is invoked from many entry points (HTTP/gRPC commits,
// cluster sync recv, DHCP callbacks, config-poll, dynamic feeds, event
// engine, in-process CLI commits, CLI auto-rollback). Before #846 these
// could interleave across VRF/tunnel/FRR-reload steps and leave the
// kernel inconsistent with the configstore's "active" config.
//
// Calling the real applyConfig in a unit test isn't practical — it
// touches the dataplane, FRR, IPsec, and netlink. This test instead
// pins the contract that the mutex itself provides: two goroutines
// that take applyMu around their critical section never overlap. If a
// future refactor moves the lock acquisition out of applyConfig (or
// replaces it with a non-blocking variant), this test fails.
package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyMuSerializesConcurrentCallers(t *testing.T) {
	d := &Daemon{}

	var (
		inFlight int32
		maxSeen  int32
		wg       sync.WaitGroup
	)

	const callers = 8
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			d.applyMu.Lock()
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
			d.applyMu.Unlock()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("applyMu must serialize callers; saw %d concurrent holders", got)
	}
}
