package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// These tests pin the #5232 / #5233 request-context cancellation contract:
// once the REST client disconnects (r.Context() cancelled), a handler that
// walks a large data structure must ABORT the walk instead of running to
// completion for a response nobody will read.
//
//   - #5232 bgpHandler: streaming a full internet BGP table (900k+ routes)
//     keeps formatting + JSON-escaping every remaining route and writing to a
//     dead connection — pure CPU/GC waste.
//   - #5233 session handlers: walking the whole conntrack BPF map keeps
//     holding per-bucket locks, contending with the live dataplane
//     session-sync path.
//
// Each test drives the handler with an already-cancelled request context over
// a large synthetic table and asserts the handler stops early. FAIL-ON-REVERT:
// remove the context checks and the handler processes every entry, flipping
// the "< N" / "no closing envelope" / "visited == N" assertions red.

// cancelledRequest returns req with an already-cancelled context attached, so
// r.Context().Err() is non-nil on the first check.
func cancelledRequest(req *http.Request) *http.Request {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return req.WithContext(ctx)
}

// countEscapedNewlines counts the number of route lines rendered into a
// streamed bgpHandler body. Each line is emitted as `...\n` and the trailing
// real newline is JSON-escaped to the two-byte sequence backslash+'n'; the
// synthetic routes contain no other escapable bytes, so this equals the number
// of route lines flushed to the wire.
func countEscapedNewlines(body []byte) int {
	return bytes.Count(body, []byte(`\n`))
}

func TestBGPRoutesStreamAbortsOnCanceledContext(t *testing.T) {
	// A table well past the 1024-route flush/check chunk so a correct abort
	// stops far short of the full table.
	const n = 5000
	routes := make([][3]string, n)
	for i := 0; i < n; i++ {
		routes[i] = [3]string{
			fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			fmt.Sprintf("192.168.%d.%d", i/256, i%256),
			fmt.Sprintf("65000 %d i", i),
		}
	}
	s := newBGPServer(t, makeFRRBGPOutput(routes))
	parsed, err := s.frr.GetBGPRoutes(context.Background())
	if err != nil {
		t.Fatalf("GetBGPRoutes: %v", err)
	}
	if len(parsed) != n {
		t.Fatalf("parsed %d routes, want %d", len(parsed), n)
	}

	// Cancelled request: the stream must abort at the first 1024-route chunk
	// boundary rather than rendering all 5000 routes.
	t.Run("canceled aborts early", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := cancelledRequest(httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil))
		s.bgpHandler(rec, req)

		body := rec.Body.Bytes()
		emitted := countEscapedNewlines(body)
		if emitted >= n {
			t.Fatalf("emitted %d route lines on cancelled context, want < %d (handler did not abort the stream)", emitted, n)
		}
		// The abort happens at the first 1024-route chunk, so at most 1024
		// route lines can have been formatted (and fewer flushed).
		if emitted > 1024 {
			t.Errorf("emitted %d route lines, want <= 1024 (abort should fire at the first chunk boundary)", emitted)
		}
		// The closing envelope `"}}` is only written after the loop
		// completes; an aborted stream must not contain it (the body is a
		// deliberately truncated write to a dead connection).
		if bytes.Contains(body, []byte("}}")) {
			t.Errorf("cancelled stream contains the closing envelope; handler streamed the whole table anyway")
		}
	})

	// Positive control: an un-cancelled request over the same table is
	// byte-for-byte the full buffered golden — the cancel check never fires
	// on the normal path, so output and ordering are unchanged.
	t.Run("normal path unchanged", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil)
		s.bgpHandler(rec, req)

		golden := bufferedBGPResponse(t, parsed)
		if !bytes.Equal(rec.Body.Bytes(), golden) {
			t.Fatalf("non-cancelled body != buffered golden (got %d bytes, want %d)", rec.Body.Len(), len(golden))
		}
		if got := countEscapedNewlines(rec.Body.Bytes()); got != n {
			t.Errorf("non-cancelled emitted %d route lines, want %d", got, n)
		}
	})
}

// cancelCountDP is an apiRuntimeDataPlane that offers a fixed number of
// synthetic forward (IsReverse==0) sessions and records how many the walk
// actually visited before it stopped. It embeds *dataplane.Manager purely to
// satisfy the methods the session handlers do not exercise here (GetSessionV4
// etc. return the Manager's "map not found" error, which enrichSessionV4
// tolerates as a no-op merge).
type cancelCountDP struct {
	*dataplane.Manager
	nV4     int
	nV6     int
	visited int
}

func (d *cancelCountDP) IsLoaded() bool { return true }

func (d *cancelCountDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.nV4; i++ {
		d.visited++
		var k dataplane.SessionKey
		var v dataplane.SessionValue // IsReverse==0 => matchV4 admits it
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func (d *cancelCountDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < d.nV6; i++ {
		d.visited++
		var k dataplane.SessionKeyV6
		var v dataplane.SessionValueV6
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func TestSessionHandlersAbortWalkOnCanceledContext(t *testing.T) {
	// A table many sampling windows past sessionWalkCancelInterval so a
	// correct abort visits far fewer than the full table.
	const n = 20 * sessionWalkCancelInterval

	cases := []struct {
		name    string
		path    string
		handler func(*Server, *httptest.ResponseRecorder, *http.Request)
	}{
		{
			name: "sessions list (offset)",
			path: "/api/v1/sessions",
			handler: func(s *Server, rr *httptest.ResponseRecorder, r *http.Request) {
				s.sessionsHandler(rr, r)
			},
		},
		{
			name: "sessions summary",
			path: "/api/v1/sessions/summary",
			handler: func(s *Server, rr *httptest.ResponseRecorder, r *http.Request) {
				s.sessionSummaryHandler(rr, r)
			},
		},
		{
			name: "sessions zone-pair",
			path: "/api/v1/sessions/zone-pair",
			handler: func(s *Server, rr *httptest.ResponseRecorder, r *http.Request) {
				s.sessionZonePairHandler(rr, r)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Cancelled: the walk must stop within one sampling window.
			dp := &cancelCountDP{Manager: dataplane.New(), nV4: n}
			s := &Server{dp: dp}
			rr := httptest.NewRecorder()
			tc.handler(s, rr, cancelledRequest(httptest.NewRequest(http.MethodGet, tc.path, nil)))

			if dp.visited >= n {
				t.Fatalf("%s: visited %d of %d sessions on cancelled context, want < %d (walk not aborted)",
					tc.name, dp.visited, n, n)
			}
			// The sampler probes ctx.Err() once per sessionWalkCancelInterval
			// entries and latches on the first cancelled probe, so exactly one
			// window is walked before the abort.
			if dp.visited != sessionWalkCancelInterval {
				t.Errorf("%s: visited %d sessions, want %d (one sampling window)",
					tc.name, dp.visited, sessionWalkCancelInterval)
			}

			// Positive control: an un-cancelled request walks the ENTIRE
			// table — the sampler never latches, so behavior is unchanged.
			dp2 := &cancelCountDP{Manager: dataplane.New(), nV4: n}
			s2 := &Server{dp: dp2}
			rr2 := httptest.NewRecorder()
			tc.handler(s2, rr2, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if dp2.visited != n {
				t.Errorf("%s: non-cancelled visited %d of %d sessions, want all %d walked",
					tc.name, dp2.visited, n, n)
			}
		})
	}
}

// cursorCountDP is the CURSOR-path analogue of cancelCountDP: it serves nV4
// forward v4 sessions and nV6 forward v6 sessions through the
// sessionCursorIterator (IterateSessionsFrom / IterateSessionsV6From) that
// s.sessionsCursor drives, counting how many of each family the walk visited
// before it stopped. The embedded *dataplane.Manager satisfies the rest of the
// apiRuntimeDataPlane surface (and its GetSessionV4/V6 "map not found" makes
// enrichSessionV4/V6 a no-op merge). cancelCountDP deliberately implements only
// the NON-cursor iterators, so sessionsCursor was never exercised and the
// cursor-path context-cancel gap remained open until #5233's closeout.
type cursorCountDP struct {
	*dataplane.Manager
	nV4, nV6             int
	visitedV4, visitedV6 int
}

func (d *cursorCountDP) IsLoaded() bool { return true }

func (d *cursorCountDP) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.nV4; i++ {
		d.visitedV4++
		var k dataplane.SessionKey
		var v dataplane.SessionValue // IsReverse==0 => matchV4 admits it
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func (d *cursorCountDP) IterateSessionsV6From(_ *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < d.nV6; i++ {
		d.visitedV6++
		var k dataplane.SessionKeyV6
		var v dataplane.SessionValueV6
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

// TestSessionsCursorAbortsWalkOnCanceledContext_5233 pins the cursor-path half
// of #5233 (the residual left open when the non-cursor handlers were guarded).
// A page_size>0 request routes to sessionsCursor via the sessionCursorIterator
// assertion; a destination_port filter that no zero-value synthetic session can
// match means the page NEVER fills, so ONLY the request-context checks can bound
// the walk — isolating the fix from the len(all)>=pageSize page cap.
//
// FAIL-ON-REVERT: drop the cancelled()/r.Context().Err() checks from
// sessionsCursor and the cancelled walks run every entry (v4 == n, v6 == n) and
// write a terminal envelope — flipping every assertion below red.
func TestSessionsCursorAbortsWalkOnCanceledContext_5233(t *testing.T) {
	const n = 20 * sessionWalkCancelInterval
	// No zero-key session matches destination_port=443, so len(all) stays 0 and
	// the page (page_size=500) never fills.
	const noMatch = "page_size=500&destination_port=443"

	t.Run("cancelled no-match stops v4 within one window and skips v6", func(t *testing.T) {
		dp := &cursorCountDP{Manager: dataplane.New(), nV4: n, nV6: n}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, cancelledRequest(httptest.NewRequest(http.MethodGet, "/api/v1/sessions?"+noMatch, nil)))

		if dp.visitedV4 != sessionWalkCancelInterval {
			t.Errorf("v4 visited %d, want %d (one sampling window before the abort)", dp.visitedV4, sessionWalkCancelInterval)
		}
		if dp.visitedV6 != 0 {
			t.Errorf("v6 visited %d, want 0 (the v6 phase must not start after a cancelled v4 walk)", dp.visitedV6)
		}
		// No envelope: the handler returned before writeSessionList, so the
		// (misleading) terminal page — AND the include_peer fan-out that
		// writeSessionList performs first — never ran on the dead connection.
		if rr.Body.Len() != 0 {
			t.Errorf("cancelled cursor walk wrote a %d-byte envelope, want none: %s", rr.Body.Len(), rr.Body.String())
		}
	})

	t.Run("cancelled v6start-token does not start the v6 walk", func(t *testing.T) {
		dp := &cursorCountDP{Manager: dataplane.New(), nV6: n}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		v6start := base64.RawURLEncoding.EncodeToString([]byte("v6start"))
		s.sessionsHandler(rr, cancelledRequest(httptest.NewRequest(http.MethodGet,
			"/api/v1/sessions?"+noMatch+"&page_token="+v6start, nil)))

		if dp.visitedV6 != 0 {
			t.Errorf("v6 visited %d on a cancelled v6start request, want 0 (the pre-v6 ctx check must fire before the walk)", dp.visitedV6)
		}
		if rr.Body.Len() != 0 {
			t.Errorf("cancelled v6start walk wrote a %d-byte envelope, want none: %s", rr.Body.Len(), rr.Body.String())
		}
	})

	t.Run("non-cancelled no-match walks BOTH families fully and writes the last page", func(t *testing.T) {
		dp := &cursorCountDP{Manager: dataplane.New(), nV4: n, nV6: n}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sessions?"+noMatch, nil))

		if dp.visitedV4 != n {
			t.Errorf("v4 visited %d, want all %d (the cancel check must be inert on the normal path)", dp.visitedV4, n)
		}
		if dp.visitedV6 != n {
			t.Errorf("v6 visited %d, want all %d", dp.visitedV6, n)
		}
		if rr.Code != http.StatusOK || rr.Body.Len() == 0 {
			t.Errorf("non-cancelled cursor walk: code=%d body=%d, want 200 with a terminal envelope", rr.Code, rr.Body.Len())
		}
	})

	// Page-token semantics preserved on the normal path: a match-all request
	// fills exactly one page and emits a v4 next_page_token (omitempty, so its
	// presence proves a resume token was issued).
	t.Run("non-cancelled match-all fills a page and issues a next-page token", func(t *testing.T) {
		dp := &cursorCountDP{Manager: dataplane.New(), nV4: n, nV6: n}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sessions?page_size=100", nil))

		if rr.Code != http.StatusOK {
			t.Fatalf("match-all cursor request: code=%d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"next_page_token"`) {
			t.Errorf("full page must emit a next_page_token (page-token semantics preserved); body: %s", rr.Body.String())
		}
		// The v4 walk stops one probe past the full page (pageSize appended, the
		// next callback observes len(all)>=pageSize) and v6 is never reached.
		if dp.visitedV4 != 101 || dp.visitedV6 != 0 {
			t.Errorf("match-all page: v4 visited %d (want 101), v6 visited %d (want 0)", dp.visitedV4, dp.visitedV6)
		}
	})
}
