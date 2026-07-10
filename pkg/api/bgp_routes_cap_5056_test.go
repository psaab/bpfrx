package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #5056: the BGP routes REST endpoint must not materialize the entire upstream
// RIB. StreamBGPRoutes scans vtysh stdout incrementally (bounded memory) and
// the handler caps the number of rendered routes at maxBGPRoutes, appending a
// truncation notice when the cap trips. This test pins the CAP contract: a
// table larger than the cap yields at most maxBGPRoutes route lines plus a
// clear truncation indicator, and the routes past the cap are absent.
//
// FAIL-ON-REVERT: drop the `count >= limit` cap in StreamBGPRoutes (or stop
// passing maxBGPRoutes from the handler) and the full table streams out — the
// "exactly cap route lines", "notice present", and "over-cap route absent"
// assertions all flip red. Proven RED in the commit message.
func TestBGPRoutesEndpointCapTruncates(t *testing.T) {
	const total = 50
	// Lower the cap so the truncation path is exercised without synthesizing a
	// million-route fixture. Restored on return.
	origCap := maxBGPRoutes
	maxBGPRoutes = 10
	defer func() { maxBGPRoutes = origCap }()

	routes := make([][3]string, total)
	for i := 0; i < total; i++ {
		routes[i] = [3]string{
			fmt.Sprintf("10.0.%d.0/24", i),
			fmt.Sprintf("192.168.0.%d", i),
			fmt.Sprintf("65000 %d i", i),
		}
	}
	s := newBGPServer(t, makeFRRBGPOutput(routes))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil)
	s.bgpHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// The truncated response is still a well-formed envelope.
	var resp struct {
		Success bool         `json:"success"`
		Data    TextResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal truncated response: %v (body=%q)", err, rec.Body.Bytes())
	}
	if !resp.Success {
		t.Errorf("success = false, want true")
	}

	lines := strings.Split(strings.TrimRight(resp.Data.Output, "\n"), "\n")

	// Partition rendered lines into route lines vs the truncation notice.
	var routeLines int
	noticeSeen := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, "... table truncated at") {
			noticeSeen = true
			continue
		}
		if strings.HasPrefix(ln, "10.0.") {
			routeLines++
		}
	}

	if routeLines != maxBGPRoutes {
		t.Errorf("rendered %d route lines, want exactly the cap %d (endpoint did not bound the table)",
			routeLines, maxBGPRoutes)
	}
	if !noticeSeen {
		t.Errorf("truncation notice missing; a bounded/truncated response must tell the client")
	}
	// A route past the cap must not appear at all — the whole RIB was not
	// materialized/emitted.
	overCap := fmt.Sprintf("10.0.%d.0/24", total-1) // index 49, well past cap 10
	if strings.Contains(resp.Data.Output, overCap) {
		t.Errorf("over-cap route %s present in output; table was not bounded", overCap)
	}

	// Sanity: routes within the cap ARE present (we truncate, not drop
	// everything).
	if !strings.Contains(resp.Data.Output, "10.0.0.0/24") {
		t.Errorf("first route missing from truncated output")
	}
}
