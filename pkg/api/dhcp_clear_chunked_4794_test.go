package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// #4794 RED-on-revert: clearDHCPIdentifiersHandler gated the JSON body
// decode on r.ContentLength > 0. A Transfer-Encoding: chunked request
// reports ContentLength == -1 (unknown length), so the old gate skipped the
// decode entirely, req.Interface stayed "", and the handler fell through to
// ClearAllDUIDs() -- wiping every DHCPv6 DUID even when the operator's body
// asked to clear ONE interface. The response "message" field is the
// observable proxy for which branch executed: a single-interface clear
// returns "DHCPv6 DUID cleared for <iface>"; a clear-all returns "All
// DHCPv6 DUIDs cleared".
//
// dhcp.NewManagerForTesting builds a *dhcp.Manager with no netlink handle
// and no persisted DUID files, so ClearDUID/ClearAllDUIDs are pure no-ops
// against an empty in-memory map -- exactly what's needed to observe ONLY
// the routing decision, not real DUID state.

func newTestDHCPManager() *dhcp.Manager {
	return dhcp.NewManagerForTesting(nil)
}

func TestClearDHCPIdentifiers_ChunkedBody_ClearsSingleInterface(t *testing.T) {
	s := &Server{dhcp: newTestDHCPManager()}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/dhcp/identifiers/clear",
		strings.NewReader(`{"interface":"ge-0/0/0.0"}`))
	req.ContentLength = -1 // simulate Transfer-Encoding: chunked

	s.clearDHCPIdentifiersHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "DHCPv6 DUID cleared for ge-0/0/0.0") {
		t.Fatalf("chunked clear-one request did not clear the named interface "+
			"(likely fell through to clear-all — #4794): %s", body)
	}
	if strings.Contains(body, "All DHCPv6 DUIDs cleared") {
		t.Fatalf("chunked clear-one request wrongly cleared ALL DUIDs — #4794: %s", body)
	}
}

// TestClearDHCPIdentifiers_KnownLengthBody_Unchanged is the no-regression
// guard: a normal (non-chunked, known Content-Length) body already worked
// before the fix and must keep working identically.
func TestClearDHCPIdentifiers_KnownLengthBody_Unchanged(t *testing.T) {
	s := &Server{dhcp: newTestDHCPManager()}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/dhcp/identifiers/clear",
		strings.NewReader(`{"interface":"ge-0/0/0.0"}`))
	// httptest.NewRequest already sets a known ContentLength for a
	// strings.Reader body; leave it untouched.

	s.clearDHCPIdentifiersHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "DHCPv6 DUID cleared for ge-0/0/0.0") {
		t.Fatalf("known-length clear-one request did not clear the named interface: %s", body)
	}
}

// TestClearDHCPIdentifiers_EmptyBody_ClearsAll is the documented "no body /
// no interface = clear all" contract, for BOTH a genuinely empty body
// (ContentLength == 0) and a chunked request that happens to carry zero
// bytes (ContentLength == -1, empty body -> Decode returns io.EOF, which
// must be tolerated rather than surfacing HTTP 400).
func TestClearDHCPIdentifiers_EmptyBody_ClearsAll(t *testing.T) {
	cases := []struct {
		name          string
		contentLength int64
	}{
		{"no body (ContentLength 0)", 0},
		{"chunked empty body (ContentLength -1)", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{dhcp: newTestDHCPManager()}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/v1/dhcp/identifiers/clear", nil)
			req.ContentLength = tc.contentLength

			s.clearDHCPIdentifiersHandler(rr, req)

			if rr.Code != 200 {
				t.Fatalf("status = %d, want 200 (empty body must not 400); body: %s",
					rr.Code, rr.Body.String())
			}
			body := rr.Body.String()
			if !strings.Contains(body, "All DHCPv6 DUIDs cleared") {
				t.Fatalf("empty-body request did not clear all: %s", body)
			}
		})
	}
}
