package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
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

// stageAddressConfig builds a Server whose active config has n distinct
// address-book entries, committed through the real LoadSet + Commit path. The
// redacted render carries one `address a<i> 10.x.y.z/32;` line per entry, all
// containing "address", so a broad query over the render matches every one —
// used to drive the configSearchHandler result cap + truncation header.
func stageAddressConfig(t *testing.T, n int) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "set security address-book global address a%05d 10.%d.%d.%d/32\n",
			i, i/65536, (i/256)%256, i%256)
	}
	if _, err := store.LoadSet(b.String()); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

// searchResultCount unmarshals a configSearchHandler response body and returns
// the number of ConfigSearchResults it carries.
func searchResultCount(t *testing.T, body []byte) int {
	t.Helper()
	var resp struct {
		Success bool                 `json:"success"`
		Data    []ConfigSearchResult `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v; body: %s", err, body)
	}
	return len(resp.Data)
}

// TestConfigSearchHandlerTruncatesResults_5250 is the fail-on-revert guard for
// the PRODUCTION result cap + truncation header (#5250 A8-b1 F2). The pure
// searchConfigLines helper is exercised above, but the maxConfigSearchResults
// cap wired into configSearchHandler and the X-Result-Truncated header it sets
// are only bound by driving the handler. With more than the cap of matching
// address lines, the response must (a) carry exactly maxConfigSearchResults
// results and (b) set X-Result-Truncated: true. Neutralizing the header Set
// fails (b); neutralizing the cap fails (a).
func TestConfigSearchHandlerTruncatesResults_5250(t *testing.T) {
	s := stageAddressConfig(t, maxConfigSearchResults+50)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config/search?q=address", nil)
	s.configSearchHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if got := searchResultCount(t, rr.Body.Bytes()); got != maxConfigSearchResults {
		t.Fatalf("result count = %d, want %d (result cap not enforced by handler)",
			got, maxConfigSearchResults)
	}
	if got := rr.Header().Get("X-Result-Truncated"); got != "true" {
		t.Fatalf("X-Result-Truncated = %q, want \"true\" (truncation header not set)", got)
	}
}

// TestConfigSearchHandlerNoTruncateHeaderUnderCap_5250 confirms the handler
// leaves the X-Result-Truncated header ABSENT when the match set fits under the
// cap — the header must track real truncation, not fire spuriously.
func TestConfigSearchHandlerNoTruncateHeaderUnderCap_5250(t *testing.T) {
	s := stageAddressConfig(t, 10)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config/search?q=address", nil)
	s.configSearchHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	// 10 address lines + the "address-book {" header line all contain
	// "address"; the exact count is not the point — it must be under the cap
	// and the header must be absent.
	if got := searchResultCount(t, rr.Body.Bytes()); got == 0 || got > maxConfigSearchResults {
		t.Fatalf("result count = %d, want a small non-zero count under the cap", got)
	}
	if got := rr.Header().Get("X-Result-Truncated"); got != "" {
		t.Fatalf("X-Result-Truncated = %q, want absent when matches <= cap", got)
	}
}
