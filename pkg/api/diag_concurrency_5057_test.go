package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// TestDiagConcurrencyLimitREST is the #5057 fail-on-revert guard for the
// REST ping/traceroute handlers. It swaps the shared diagLimiter for a
// fresh small-capacity limiter and injects a fake slow diagnostic via
// the diagRun seam, then fires cap+excess concurrent requests. It
// asserts:
//   - at most `cap` handlers run the diagnostic concurrently,
//   - the `excess` requests are rejected immediately with HTTP 429
//     (not queued, not hung, not admitted),
//   - after the admitted diagnostics finish the limiter is fully
//     released, so a subsequent request succeeds.
//
// RED-on-revert: remove the diagLimiter.Acquire()/429 branch from the
// handlers and every request is admitted — rejected drops to 0 and the
// max-concurrency assertion fires.
func TestDiagConcurrencyLimitREST(t *testing.T) {
	const (
		cap    = 2
		excess = 5
	)

	// Isolate from the process-wide DefaultLimiter.
	origLimiter := diagLimiter
	origRun := diagRun
	t.Cleanup(func() { diagLimiter = origLimiter; diagRun = origRun })
	diagLimiter = diagcmd.NewLimiter(cap)

	const total = cap + excess

	var (
		inFlight    int32
		maxObserved int32
		attempts    int32
	)
	gate := make(chan struct{})         // holds each fake diagnostic until closed
	allAttempted := make(chan struct{}) // closed once every request has attempted Acquire
	var once sync.Once
	noteAttempt := func() {
		if atomic.AddInt32(&attempts, 1) == total {
			once.Do(func() { close(allAttempted) })
		}
	}

	diagRun = func(ctx context.Context, argv []string) (string, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			m := atomic.LoadInt32(&maxObserved)
			if cur <= m || atomic.CompareAndSwapInt32(&maxObserved, m, cur) {
				break
			}
		}
		noteAttempt() // admitted: reached the diagnostic, now holding a slot
		select {
		case <-gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		return "ok", nil
	}

	s := &Server{}
	fire := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/ping",
			strings.NewReader(`{"target":"192.0.2.1"}`))
		rec := httptest.NewRecorder()
		s.pingHandler(rec, req)
		return rec.Code
	}

	codes := make([]int, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := fire()
			if c == http.StatusTooManyRequests {
				noteAttempt() // rejected: fail-fast, counts as an attempt
			}
			codes[idx] = c
		}(i)
	}

	// Hold the gate until every request has attempted Acquire, so no
	// admitted request frees its slot before the excess have been
	// rejected (which would let an excess request win a freed slot).
	select {
	case <-allAttempted:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %d attempts; inFlight=%d attempts=%d",
			total, atomic.LoadInt32(&inFlight), atomic.LoadInt32(&attempts))
	}

	close(gate)
	wg.Wait()

	var ok, tooMany, other int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			tooMany++
		default:
			other++
		}
	}
	if other != 0 {
		t.Fatalf("unexpected status codes present: %v", codes)
	}
	if tooMany != excess {
		t.Fatalf("429 count = %d, want %d (excess must be rejected, not queued): %v",
			tooMany, excess, codes)
	}
	if ok != cap {
		t.Fatalf("200 count = %d, want %d: %v", ok, cap, codes)
	}
	if m := atomic.LoadInt32(&maxObserved); m > cap {
		t.Fatalf("max concurrent diagnostics = %d, want <= %d", m, cap)
	}

	// Limiter fully released: a subsequent request must succeed.
	if code := fire(); code != http.StatusOK {
		t.Fatalf("post-drain request status = %d, want 200 (limiter not released)", code)
	}
}

// TestDiagConcurrencyLimitSharedAcrossPingTraceroute proves ping and
// traceroute draw from the SAME limiter: a ping holding the only slot
// makes a concurrent traceroute get 429.
func TestDiagConcurrencyLimitSharedAcrossPingTraceroute(t *testing.T) {
	origLimiter := diagLimiter
	origRun := diagRun
	t.Cleanup(func() { diagLimiter = origLimiter; diagRun = origRun })
	diagLimiter = diagcmd.NewLimiter(1)

	entered := make(chan struct{})
	gate := make(chan struct{})
	diagRun = func(ctx context.Context, argv []string) (string, error) {
		close(entered)
		<-gate
		return "ok", nil
	}

	// Occupy the single slot with a ping.
	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/ping",
			strings.NewReader(`{"target":"192.0.2.1"}`))
		rec := httptest.NewRecorder()
		(&Server{}).pingHandler(rec, req)
		done <- rec.Code
	}()
	<-entered

	// A concurrent traceroute must be rejected — shared cap.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/traceroute",
		strings.NewReader(`{"target":"192.0.2.1"}`))
	rec := httptest.NewRecorder()
	(&Server{}).tracerouteHandler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent traceroute status = %d, want 429 (shared limiter)", rec.Code)
	}

	close(gate)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("ping status = %d, want 200", code)
	}
}
