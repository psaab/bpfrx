package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #8597 (muse-spark-review-004 K89): `Origin: null` must be treated as a
// mismatch, not exempted from the host check.
//
// The guard carried `!strings.EqualFold(origin, "null")` on its Origin arm, so
// a mutation request carrying `Origin: null` skipped check (b) entirely.
//
// WHY THAT IS THE WRONG EXEMPTION. `null` is not a neutral or absent value — it
// is what a browser sends specifically from the contexts an attacker controls:
// a sandboxed iframe (`sandbox` without `allow-same-origin`), a `data:` or
// `file:` document, and a cross-origin redirect. The one Origin value that
// names an opaque provenance was the one value waved through.
//
// It also contradicted this file's own stated policy, three paragraphs above
// the code: "Origin ... Rejected when present and its host:port differs from
// the target." `null` differs from every host. A carve-out the policy does not
// mention is the shape review cannot see, because the prose reads correct.
//
// WHAT FAILING CLOSED COSTS, since that is the question a security tightening
// owes: nothing reachable. A non-browser client — curl, the CLI, a scraper —
// sends no Origin header at all and is unaffected, which the "programmatic"
// rows of `crosssite_5055_test.go` already cover and which the control below
// re-asserts. The management UI is same-origin. The only requests newly
// rejected are those whose provenance is opaque, which is the definition of the
// thing being detected.

func TestNullOriginIsRejected_8597(t *testing.T) {
	const target = "http://127.0.0.1:8080/api/v1/config/set"
	h := guardedOK()

	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{
			// THE SUBJECT.
			name:    "null origin is rejected",
			headers: map[string]string{"Origin": "null", "Content-Type": "application/json"},
			want:    http.StatusForbidden,
		},
		{
			// Case-insensitively, because the old carve-out used EqualFold and a
			// half-fix that only matched the lowercase spelling would pass the
			// row above.
			name:    "NULL origin is rejected too",
			headers: map[string]string{"Origin": "NULL", "Content-Type": "application/json"},
			want:    http.StatusForbidden,
		},
		{
			// CONTROL 1: the programmatic client. This is what the carve-out
			// might have been protecting, and it does not need protecting —
			// it sends no Origin at all.
			name:    "programmatic client with no Origin still passes",
			headers: map[string]string{"Content-Type": "application/json"},
			want:    http.StatusOK,
		},
		{
			// CONTROL 2: the management UI. If this ever fails, the tightening
			// has broken the one browser client that must work, and the two
			// rejections above would be measuring an unusable guard.
			name: "same-origin browser request still passes",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Origin":         "http://127.0.0.1:8080",
				"Content-Type":   "application/json",
			},
			want: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
