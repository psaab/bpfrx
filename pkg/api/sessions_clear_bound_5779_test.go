// #5779: the REST session-clear endpoint's local-only fallback drives a
// full-table chunked clear-all walk (ClearAllSessions), the same per-bucket
// BPF-map lock contention DoS class as the #5433/#5708 read scans, on the
// mutation path. The fix gates that fallback through the SAME shared
// sessionWalkLimiter (HTTP 429 on over-cap).
//
// FAIL-ON-REVERT: removing the sessionWalkLimiter.Acquire()/429 branch from the
// clear fallback makes the over-cap request reach ClearAllSessions and return
// 200 (cleared), flipping the want-429/no-walk assertions red.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

func TestRESTClearSessionsConcurrencyBound(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1) // single slot

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	// clusterSessionFn nil -> clusterSession() nil -> the local-only
	// ClearAllSessions fallback (the path this gate guards).
	dp := &clearAllDP{Manager: dataplane.New()}
	s := &Server{dp: dp}

	// Over-cap: rejected 429, and the clear-all walk must NOT run.
	rr := httptest.NewRecorder()
	s.clearSessionsHandler(rr, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	if rr.Code != http.StatusTooManyRequests {
		release()
		t.Fatalf("clear status = %d while the limiter is saturated, want 429; body: %s", rr.Code, rr.Body.String())
	}
	if dp.cleared {
		release()
		t.Fatal("clear-all walk ran despite the limiter being saturated (gate not consulted)")
	}

	// Free the slot; the next clear must be admitted (200) and run the walk.
	release()
	rr2 := httptest.NewRecorder()
	s.clearSessionsHandler(rr2, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("clear status = %d after slot release, want 200; body: %s", rr2.Code, rr2.Body.String())
	}
	if !dp.cleared {
		t.Fatal("clear-all did not run after admission")
	}
}
