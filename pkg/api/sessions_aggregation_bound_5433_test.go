package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// runSessionWalkConcurrencyBound drives cap+excess concurrent requests through
// a full-table-walk session handler and asserts the shared sessionWalkLimiter:
//   - admits at most `cap` walks concurrently,
//   - rejects the `excess` requests immediately with HTTP 429 (fail-fast, not
//     queued),
//   - fully releases after the admitted walks drain, so a subsequent request
//     succeeds (no permit leaked on the 429 or success paths).
//
// It reuses blockingSessionDP (sessions_pagination_bound_5318_test.go), whose
// IterateSessions blocks on a gate so the test can pin `cap` handlers inside
// their walk at once. Mirrors TestRESTSessionListConcurrencyBound for the
// summary/zone-pair siblings (#5433).
//
// RED-on-revert: remove the sessionWalkLimiter.Acquire()/429 branch from the
// handler under test and every request is admitted — the 429 count drops to 0
// and the max-concurrency assertion fires.
func runSessionWalkConcurrencyBound(t *testing.T, path string,
	invoke func(*Server, http.ResponseWriter, *http.Request)) {
	t.Helper()

	const (
		capN   = 2
		excess = 5
		total  = capN + excess
	)

	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(capN)

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
		invoke(s, rr, httptest.NewRequest("GET", path, nil))
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

	// Permit release: after the 429 burst and drain, a subsequent request must
	// succeed — proving no slot leaked on the 429 or success paths.
	if code := fire(); code != http.StatusOK {
		t.Fatalf("post-drain request status = %d, want 200 (limiter not released)", code)
	}
}

// TestRESTSessionSummaryConcurrencyBound pins the #5433 admission contract for
// the /security/sessions/summary aggregation handler: like the list sibling
// (#5318) it walks the whole v4+v6 conntrack table, so concurrent scrapes must
// be bounded by the shared sessionWalkLimiter rather than each driving its own
// full walk.
func TestRESTSessionSummaryConcurrencyBound(t *testing.T) {
	runSessionWalkConcurrencyBound(t, "/api/v1/security/sessions/summary",
		func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.sessionSummaryHandler(w, r)
		})
}

// TestRESTSessionZonePairConcurrencyBound pins the #5433 admission contract for
// the /security/sessions/summary/zone-pairs aggregation handler (same full
// v4+v6 walk, same shared gate).
func TestRESTSessionZonePairConcurrencyBound(t *testing.T) {
	runSessionWalkConcurrencyBound(t, "/api/v1/security/sessions/summary/zone-pairs",
		func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.sessionZonePairHandler(w, r)
		})
}

// TestRESTSessionWalkLimiterShared asserts the list, summary, and zone-pair
// handlers draw from ONE shared limiter (#5433): saturating the limiter with
// summary walks makes a concurrent list request 429, proving the aggregate
// bound covers all three scan endpoints rather than one budget per endpoint.
func TestRESTSessionWalkLimiterShared(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1) // single slot: any second walk 429s

	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	dp := &blockingSessionDP{
		Manager: dataplane.New(),
		gate:    gate,
		enter: func() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
		},
	}
	s := &Server{dp: dp}

	// Hold the single slot with a summary walk.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rr := httptest.NewRecorder()
		s.sessionSummaryHandler(rr, httptest.NewRequest("GET",
			"/api/v1/security/sessions/summary", nil))
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(gate)
		wg.Wait()
		t.Fatal("summary walk never entered the table scan")
	}

	// The slot is held by the summary walk; a concurrent LIST request must be
	// rejected by the SAME limiter.
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions", nil))
	if rr.Code != http.StatusTooManyRequests {
		close(gate)
		wg.Wait()
		t.Fatalf("list status = %d while a summary walk holds the shared slot; want 429 (limiter not shared)",
			rr.Code)
	}

	close(gate)
	wg.Wait()
}
