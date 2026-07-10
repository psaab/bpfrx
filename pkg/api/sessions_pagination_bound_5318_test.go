package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// TestRESTSessionListBoundsTotalWalk pins the #5318 bounded-Total contract:
// the default (no page_size) offset list must NOT walk the whole v4+v6 table
// per page just to report an exact Total. It caps the count at sessionCountCap
// matching rows — under the cap Total stays EXACT and the response is
// byte-identical (total_approximate omitted); past the cap the walk stops and
// Total is reported as an approximate lower bound with total_approximate=true.
//
// It reuses cancelCountDP (api_ctx_cancel_5232_5233_test.go), which yields a
// fixed number of forward (IsReverse==0, so matchV4/V6-admitted) sessions and
// records how many the walk actually visited before stopping.
//
// RED-on-revert: restore sessionsOffset to the unbounded idx walk (count every
// row, always walk v6). The large-table case then visits the whole 1100-row
// table (visited==1100, not sessionCountCap+1) and reports total_approximate
// false, flipping both assertions red.
func TestRESTSessionListBoundsTotalWalk(t *testing.T) {
	origCap := sessionCountCap
	t.Cleanup(func() { sessionCountCap = origCap })
	sessionCountCap = 200

	t.Run("large table caps the walk and flags approximate", func(t *testing.T) {
		// nV4 (1000) alone exceeds the cap; nV6 (100) must be skipped entirely.
		dp := &cancelCountDP{Manager: dataplane.New(), nV4: 1000, nV6: 100}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		// limit=100, offset=0 => countCap = max(200, 100) = 200.
		s.sessionsHandler(rr, httptest.NewRequest("GET",
			"/api/v1/security/sessions?limit=100", nil))
		if rr.Code != 200 {
			t.Fatalf("status %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		resp := decodeSessions(t, rr.Body.Bytes())

		// The walk stops one past the cap on the v4 leg; v6 is never entered.
		if dp.visited != sessionCountCap+1 {
			t.Fatalf("visited %d of 1100 sessions, want %d (walk not bounded to the cap)",
				dp.visited, sessionCountCap+1)
		}
		if !resp.TotalApproximate {
			t.Fatalf("total_approximate=false on a table larger than the cap; want true")
		}
		if resp.Total != sessionCountCap+1 {
			t.Fatalf("Total=%d, want %d (capped lower bound)", resp.Total, sessionCountCap+1)
		}
		// The page must still fill to the requested limit even when capped.
		if len(resp.Sessions) != 100 {
			t.Fatalf("returned %d rows, want 100 (page must fill despite the cap)",
				len(resp.Sessions))
		}
		if !bytes.Contains(rr.Body.Bytes(), []byte(`"total_approximate":true`)) {
			t.Fatalf("wire body missing total_approximate flag: %s", rr.Body.String())
		}
	})

	t.Run("small table exact Total, byte-compatible", func(t *testing.T) {
		// 30 v4 + 10 v6 = 40 matches, well under the cap.
		dp := &cancelCountDP{Manager: dataplane.New(), nV4: 30, nV6: 10}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, httptest.NewRequest("GET",
			"/api/v1/security/sessions?limit=100", nil))
		if rr.Code != 200 {
			t.Fatalf("status %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		resp := decodeSessions(t, rr.Body.Bytes())

		// A table under the cap is walked in full (exact Total).
		if dp.visited != 40 {
			t.Fatalf("visited %d, want 40 (small table must be walked in full)", dp.visited)
		}
		if resp.TotalApproximate {
			t.Fatalf("total_approximate=true on a small table; want exact Total")
		}
		if resp.Total != 40 {
			t.Fatalf("Total=%d, want 40 (exact)", resp.Total)
		}
		if len(resp.Sessions) != 40 {
			t.Fatalf("returned %d rows, want 40", len(resp.Sessions))
		}
		// Backward compatibility: omitempty keeps total_approximate off the wire
		// for the common case, so an existing client sees the pre-#5318 shape.
		if bytes.Contains(rr.Body.Bytes(), []byte("total_approximate")) {
			t.Fatalf("small-table body leaked total_approximate; want omitted: %s",
				rr.Body.String())
		}
	})
}

// blockingSessionDP is an apiRuntimeDataPlane whose session walk blocks until a
// gate is released, so a test can hold N handlers inside their walk at once and
// observe the admission limiter. enter() runs at the top of IterateSessions
// (before the block) to record concurrency.
type blockingSessionDP struct {
	*dataplane.Manager
	enter func()
	gate  chan struct{}
}

func (d *blockingSessionDP) IsLoaded() bool { return true }

func (d *blockingSessionDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.enter()
	<-d.gate
	return nil
}

func (d *blockingSessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// TestRESTSessionListConcurrencyBound pins the #5318 admission contract for the
// session list handler, mirroring the #5057 diagnostic-limiter test. It swaps
// sessionsListLimiter for a fresh small-capacity limiter and drives cap+excess
// concurrent list requests through a walk that blocks on a gate. It asserts:
//   - at most `cap` handlers run the walk concurrently,
//   - the `excess` requests are rejected immediately with HTTP 429 (not queued),
//   - after the admitted walks finish the limiter is fully released, so a
//     subsequent request succeeds.
//
// RED-on-revert: remove the sessionsListLimiter.Acquire()/429 branch from
// sessionsHandler and every request is admitted — the 429 count drops to 0 and
// the max-concurrency assertion fires.
func TestRESTSessionListConcurrencyBound(t *testing.T) {
	const (
		capN   = 2
		excess = 5
		total  = capN + excess
	)

	orig := sessionsListLimiter
	t.Cleanup(func() { sessionsListLimiter = orig })
	sessionsListLimiter = diagcmd.NewLimiter(capN)

	var (
		inFlight    int32
		maxObserved int32
		attempts    int32
	)
	gate := make(chan struct{})         // holds each admitted walk until closed
	allAttempted := make(chan struct{}) // closed once every request has attempted Acquire
	var once sync.Once
	noteAttempt := func() {
		if atomic.AddInt32(&attempts, 1) == total {
			once.Do(func() { close(allAttempted) })
		}
	}

	dp := &blockingSessionDP{
		Manager: dataplane.New(),
		gate:    gate,
		enter: func() {
			cur := atomic.AddInt32(&inFlight, 1)
			defer atomic.AddInt32(&inFlight, -1)
			for {
				m := atomic.LoadInt32(&maxObserved)
				if cur <= m || atomic.CompareAndSwapInt32(&maxObserved, m, cur) {
					break
				}
			}
			noteAttempt() // admitted: reached the walk, holding a slot
			<-gate
		},
	}
	s := &Server{dp: dp}

	fire := func() int {
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions", nil))
		return rr.Code
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

	// Hold the gate until every request has attempted Acquire, so no admitted
	// walk frees its slot before the excess have been rejected (which would let
	// an excess request win a freed slot).
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
	if ok != capN {
		t.Fatalf("200 count = %d, want %d: %v", ok, capN, codes)
	}
	if m := atomic.LoadInt32(&maxObserved); m > capN {
		t.Fatalf("max concurrent session walks = %d, want <= %d", m, capN)
	}

	// Limiter fully released: a subsequent request must succeed.
	if code := fire(); code != http.StatusOK {
		t.Fatalf("post-drain request status = %d, want 200 (limiter not released)", code)
	}
}
