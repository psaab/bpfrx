package api

import (
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// matchStatus runs matchPoliciesHandler against a raw (possibly duplicate-keyed)
// query string and returns the HTTP status + body without asserting 200, so the
// #3709 fail-closed 400 paths can be checked.
func matchStatus(t *testing.T, s *Server, rawQuery string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+rawQuery, nil)
	s.matchPoliciesHandler(rr, req)
	return rr.Code, rr.Body.String()
}

// TestMatchPoliciesRESTRejectsDuplicate is the #3709 RED-on-revert guard for the
// REST surface. r.URL.Query().Get returns the FIRST of repeated values, so a
// duplicate scalar selector (`?from_zone=trust&from_zone=dmz`) silently
// FIRST-won while the CLI/gRPC surfaces last-won — the three disagreed on WHICH
// duplicate the simulator tested. REST now rejects a repeated scalar selector
// with 400.
//
// FAIL-ON-REVERT: removing the len(q[key]) > 1 guard makes the duplicate query
// silently first-win and return 200, flipping the want-400 assertions red.
func TestMatchPoliciesRESTRejectsDuplicate(t *testing.T) {
	s := &Server{store: hostInboundAPIStore(t)}
	cases := []string{
		"from_zone=trust&from_zone=dmz&to_zone=untrust",
		"from_zone=trust&to_zone=untrust&dst_port=80&dst_port=443",
		"from_zone=trust&to_zone=untrust&protocol=tcp&protocol=udp",
		"from_zone=trust&to_zone=untrust&src_ip=10.0.0.1&src_ip=10.0.0.2",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			code, body := matchStatus(t, s, raw)
			if code != 400 {
				t.Fatalf("status = %d, want 400 (duplicate selector); body: %s", code, body)
			}
			if !strings.Contains(body, "specified more than once") {
				t.Fatalf("body = %s, want a duplicate-selector error", body)
			}
		})
	}

	// A single occurrence of each selector still succeeds.
	code, body := matchStatus(t, s, url.Values{
		"from_zone": {"trust"}, "to_zone": {"untrust"}, "dst_port": {"443"},
	}.Encode())
	if code != 200 {
		t.Fatalf("single-valued query status = %d, want 200; body: %s", code, body)
	}
}

// TestMatchPoliciesRESTNilConfigGrammarOrdering is the #3709 RED-on-revert guard
// for the no-config ordering gap: matchPoliciesHandler used to return 200
// default-deny in the cfg == nil branch BEFORE any grammar validation, so a
// malformed / duplicate query returned 200 at boot but 400 once a config
// existed — inconsistent validation exactly when monitors poll. Grammar checks
// now run BEFORE the cfg == nil verdict, so a malformed boot-window query returns
// 400 identically.
//
// FAIL-ON-REVERT: moving the cfg == nil branch back above the grammar checks
// makes these malformed boot-window queries return 200, flipping the want-400
// assertions red.
func TestMatchPoliciesRESTNilConfigGrammarOrdering(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}
	if store.ActiveConfig() != nil {
		t.Skip("active config is not nil; nil-config path not exercised")
	}

	cases := []struct {
		name string
		raw  string
	}{
		{"malformed dst_port", "from_zone=trust&to_zone=untrust&dst_port=abc"},
		{"duplicate selector", "from_zone=trust&from_zone=dmz&to_zone=untrust"},
		{"missing zones", "src_ip=10.0.0.1"},
		{"invalid src_ip", "from_zone=trust&to_zone=untrust&src_ip=10.0.0.999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := matchStatus(t, s, tc.raw)
			if code != 400 {
				t.Fatalf("no-config %s: status = %d, want 400 (grammar before cfg==nil verdict); body: %s", tc.name, code, body)
			}
		})
	}

	// A well-formed boot-window query still returns the 200 fail-closed default
	// deny (grammar-valid input is unaffected by the reorder).
	code, body := matchStatus(t, s, "from_zone=trust&to_zone=untrust")
	if code != 200 {
		t.Fatalf("well-formed no-config query status = %d, want 200 default-deny; body: %s", code, body)
	}
}
