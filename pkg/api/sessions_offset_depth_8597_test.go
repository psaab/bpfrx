package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/psaab/xpf/pkg/dataplane"
	"testing"
)

// #8597 (muse-spark-review-004 K25): `offset` must have a ceiling, because the
// countCap raise below it is driven by that parameter.
//
// #5318 bounds the Total-counting walk at `sessionCountCap` so a session list
// stops being an O(table) v4+v6 scan on every 100-row page. The offset handler
// then RAISES that cap to `offset + limit`, so that an explicitly requested deep
// window is not truncated. With `offset` unbounded, one query string sets the
// cap arbitrarily high and the #5318 bound is simply off — the full-table walk
// per page is back, on demand.
//
// The asymmetry is what makes this decidable without a trace: `limit`, parsed
// three lines above in the same function, is clamped to 10000. `offset` was
// parsed the same way and clamped by nothing.
//
// REJECTED rather than clamped, and that is the opposite of what `limit` does:
// a clamped limit returns fewer rows than asked for, which a paging client
// handles; a clamped offset returns a DIFFERENT PAGE than asked for, and a
// client walking pages would loop on it forever. Past the cap the offset path
// has nothing stable to return anyway — it is documented as best-effort because
// the backend iterates helper map order.
//
// The cells drive the real handler through the real query string. A cell that
// called a bounds helper would not notice the handler failing to consult it.

func sessionsOffsetStatus(t *testing.T, s *Server, query string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?"+query, nil)
	s.sessionsHandler(rec, req)
	return rec.Code, rec.Body.String()
}

func TestSessionOffsetDepthIsBounded_8597(t *testing.T) {
	s := NewServer(Config{Addr: "127.0.0.1:0", Store: newConfigStore(t, t.TempDir()+"/xpf.conf")})
	// A LOADED dataplane is required: the handler answers 503 before it parses
	// any query parameter, so without one every row below would assert against
	// the same short-circuit and the cell would be vacuous.
	s.dp = &oneSessionDP{Manager: dataplane.New()}

	// PREMISE: the cap this bound is expressed in terms of must be a real,
	// positive value, or every assertion below is about an accidental zero.
	if sessionCountCap <= 0 {
		t.Fatalf("PREMISE: sessionCountCap = %d", sessionCountCap)
	}

	for _, tc := range []struct {
		name  string
		query string
		want  int
	}{
		{
			// THE SUBJECT: an offset past the count cap sets countCap to
			// itself, which is #5318 turned off by a query parameter.
			name:  "offset past the cap is rejected",
			query: fmt.Sprintf("offset=%d&limit=10", sessionCountCap+1),
			want:  http.StatusBadRequest,
		},
		{
			// BOUNDARY, the row a fix written as `>=` would fail: exactly at
			// the cap is still admissible, so the rejection is not off by one
			// against a legitimate deep-but-bounded page.
			name:  "offset exactly at the cap is admitted",
			query: fmt.Sprintf("offset=%d&limit=10", sessionCountCap),
			want:  http.StatusOK,
		},
		{
			// CONTROL: ordinary paging must be untouched. If this ever fails,
			// the bound has broken the common case and the rejection above is
			// measuring an unusable handler.
			name:  "ordinary paging is unaffected",
			query: "offset=0&limit=100",
			want:  http.StatusOK,
		},
		{
			// CONTROL: the existing fail-closed parse (#3421 M8) must keep its
			// own error rather than being swallowed by the new one.
			name:  "malformed offset still fails closed",
			query: "offset=notanumber",
			want:  http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := sessionsOffsetStatus(t, s, tc.query)
			if code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", code, tc.want, body)
			}
			if tc.want == http.StatusBadRequest && tc.name == "offset past the cap is rejected" {
				// The error must name the alternative, or an operator hitting
				// it has no next step. A bare 400 would satisfy the status
				// assertion alone.
				var resp struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal([]byte(body), &resp); err != nil {
					t.Fatalf("decode error body: %v (%s)", err, body)
				}
				if resp.Error == "" {
					t.Fatalf("the rejection must carry an error message; got %s", body)
				}
				if !containsAll(resp.Error, "page_token") {
					t.Errorf("#8597: the deep-offset rejection must name the cursor path as the "+
						"alternative; got %q", resp.Error)
				}
			}
		})
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
