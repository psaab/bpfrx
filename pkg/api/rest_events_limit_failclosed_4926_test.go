package api

import (
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// TestRESTEventsLimitFailsClosed pins the #4926 fix: the security-events
// `limit` query parameter must FAIL CLOSED with HTTP 400 on a present-but-
// malformed, negative, or over-cap value, mirroring the sibling `zone`
// filter — instead of silently defaulting to 50 (the lenient queryInt
// behavior, a fail-open that hid a client bug and could under-report the
// event window). An ABSENT `limit` still defaults to 50, and a valid limit
// in [0..10000] is used as-is.
//
// FAIL-ON-REVERT: restoring `limit := queryInt(r,"limit",50)` +
// `if limit > 10000 { limit = 10000 }` makes limit=-1 / limit=abc parse to
// the 50 default (HTTP 200) and limit=10001 silently clamp to 10000
// (HTTP 200), flipping every want-400 case in this table red.
func TestRESTEventsLimitFailsClosed(t *testing.T) {
	eb := logging.NewEventBuffer(64)
	// Seed 20 distinct events so a "requested scope" assertion below (limit=5)
	// is observably smaller than the seeded count AND the default (50) window.
	for i := 0; i < 20; i++ {
		eb.Add(logging.EventRecord{Type: "SESSION_OPEN", Protocol: "TCP", Action: "permit"})
	}
	s := &Server{eventBuf: eb}

	statusCases := []struct {
		name string
		url  string
		want int
	}{
		{"limit negative", "/api/v1/security/events?limit=-1", 400},
		{"limit malformed", "/api/v1/security/events?limit=abc", 400},
		{"limit over cap", "/api/v1/security/events?limit=10001", 400},
		{"limit signed", "/api/v1/security/events?limit=%2B5", 400}, // "+5" — non-canonical
		{"limit at cap", "/api/v1/security/events?limit=10000", 200},
		{"limit valid small", "/api/v1/security/events?limit=5", 200},
		{"limit absent default", "/api/v1/security/events", 200},
	}
	for _, tc := range statusCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.eventsHandler(rr, httptest.NewRequest("GET", tc.url, nil))
			if rr.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d; body: %s",
					tc.name, rr.Code, tc.want, rr.Body.String())
			}
		})
	}

	// Scope assertions: a valid explicit limit is honored (not silently the
	// 50 default), and an absent limit falls back to the 50 default (returns
	// all 20 seeded events, capped by the buffer contents).
	scopeCases := []struct {
		name string
		url  string
		want int
	}{
		{"limit=5 returns exactly 5", "/api/v1/security/events?limit=5", 5},
		{"absent returns default window (all 20)", "/api/v1/security/events", 20},
		{"limit=10000 returns all 20", "/api/v1/security/events?limit=10000", 20},
	}
	for _, tc := range scopeCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.eventsHandler(rr, httptest.NewRequest("GET", tc.url, nil))
			if rr.Code != 200 {
				t.Fatalf("%s: status = %d, want 200; body: %s", tc.name, rr.Code, rr.Body.String())
			}
			got := len(decodeEvents(t, rr.Body.Bytes()))
			if got != tc.want {
				t.Fatalf("%s: returned %d events, want %d", tc.name, got, tc.want)
			}
		})
	}
}
