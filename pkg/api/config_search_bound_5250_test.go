package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSearchConfigLinesTruncates_5250 is the fail-on-revert guard for the
// result-count cap (#5250 A8-b1 F2). With 10 matching lines and a cap of 3, the
// helper must return exactly 3 results AND report truncated=true. Removing the
// cap makes it return all 10 with truncated=false, failing both assertions.
func TestSearchConfigLinesTruncates_5250(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("match here\n")
	}
	results, truncated := searchConfigLines(b.String(), "match", 3)
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3 (result cap not enforced)", len(results))
	}
	if !truncated {
		t.Fatal("truncated = false, want true (more matches existed past the cap)")
	}
}

// TestSearchConfigLinesNoTruncateUnderCap_5250 confirms an in-bound match set is
// returned whole with truncated=false — the cap must not spuriously trip.
func TestSearchConfigLinesNoTruncateUnderCap_5250(t *testing.T) {
	results, truncated := searchConfigLines("a\nmatch\nb\n", "match", 3)
	if len(results) != 1 || truncated {
		t.Fatalf("results=%d truncated=%v, want 1 / false", len(results), truncated)
	}
}

// TestConfigSearchHandlerRejectsLongQuery_5250 is the fail-on-revert guard for
// the q-length cap (#5250 A8-b1 F2). An over-long q must be rejected with 400
// before any render/scan. A real store is staged so that removing the cap lets
// the handler fall through to a clean 200 (the assertion fails on the code, not
// on a nil-store crash).
func TestConfigSearchHandlerRejectsLongQuery_5250(t *testing.T) {
	s, _ := stageSecretConfig(t)
	rr := httptest.NewRecorder()
	q := strings.Repeat("x", maxConfigSearchQueryLen+1)
	req := httptest.NewRequest("GET", "/api/v1/config/search?q="+q, nil)
	s.configSearchHandler(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400 for an over-long q (len %d)", rr.Code, len(q))
	}
}
