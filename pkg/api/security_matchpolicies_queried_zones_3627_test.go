package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// queriedZonesResponse decodes the REST /security/match envelope focusing on the
// #3627 M06 queried-zone echo.
type queriedZonesResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched              bool   `json:"matched"`
		HostInboundUnmatched bool   `json:"host_inbound_unmatched"`
		DefaultUsed          bool   `json:"default_used"`
		QueriedFromZone      string `json:"queried_from_zone"`
		QueriedToZone        string `json:"queried_to_zone"`
	} `json:"data"`
}

func matchQueriedZones(t *testing.T, s *Server, q url.Values) queriedZonesResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp queriedZonesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp
}

// TestMatchPoliciesRESTEchoesQueriedZones pins #3627 M06 on the REST surface:
// the match-policies response must echo the QUERIED from-zone/to-zone on EVERY
// answer — positive match, no-match/default, and host-inbound — so a stored
// JSON diagnostic proves which zone pair was tested without also capturing the
// request URL.
//
// RED-on-revert: dropping the QueriedFromZone/QueriedToZone assignment from any
// of the return paths in matchPoliciesHandler zeroes the echoed field and the
// corresponding assertion below fails.
func TestMatchPoliciesRESTEchoesQueriedZones(t *testing.T) {
	store := hostInboundAPIStore(t)
	s := &Server{store: store}

	// No-match / default: untrust->trust has no rule -> default deny.
	dd := matchQueriedZones(t, s, url.Values{"from_zone": {"untrust"}, "to_zone": {"trust"}})
	if dd.Data.Matched {
		t.Fatalf("matched = true, want false (default deny)")
	}
	if !dd.Data.DefaultUsed {
		t.Fatalf("default_used = false, want true")
	}
	if dd.Data.QueriedFromZone != "untrust" || dd.Data.QueriedToZone != "trust" {
		t.Errorf("default path queried zones = %q->%q, want untrust->trust",
			dd.Data.QueriedFromZone, dd.Data.QueriedToZone)
	}

	// Host-inbound: to-zone junos-host with no host policy -> local delivery.
	hi := matchQueriedZones(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}})
	if !hi.Data.HostInboundUnmatched {
		t.Fatalf("host_inbound_unmatched = false, want true; got %+v", hi.Data)
	}
	if hi.Data.QueriedFromZone != "trust" || hi.Data.QueriedToZone != "junos-host" {
		t.Errorf("host-inbound path queried zones = %q->%q, want trust->junos-host",
			hi.Data.QueriedFromZone, hi.Data.QueriedToZone)
	}

	// Positive match: trust->untrust permit.
	m := matchQueriedZones(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}})
	if !m.Data.Matched {
		t.Fatalf("matched = false, want true (trust->untrust permit)")
	}
	if m.Data.QueriedFromZone != "trust" || m.Data.QueriedToZone != "untrust" {
		t.Errorf("matched path queried zones = %q->%q, want trust->untrust",
			m.Data.QueriedFromZone, m.Data.QueriedToZone)
	}
}

// TestMatchPoliciesRESTNilConfigEchoesQueriedZones pins #3627 M06 on the
// no-active-config fail-closed path: the deny (default) verdict must still echo
// the queried zone pair.
//
// RED-on-revert: dropping the QueriedFromZone/QueriedToZone assignment from the
// nil-config branch zeroes the echoed field and the assertion fails.
func TestMatchPoliciesRESTNilConfigEchoesQueriedZones(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}
	if store.ActiveConfig() != nil {
		t.Skip("active config is not nil; nil-config path not exercised")
	}

	dd := matchQueriedZones(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}})
	if !dd.Data.DefaultUsed {
		t.Fatalf("default_used = false, want true (no-config fail-closed default deny)")
	}
	if dd.Data.QueriedFromZone != "trust" || dd.Data.QueriedToZone != "untrust" {
		t.Errorf("nil-config path queried zones = %q->%q, want trust->untrust",
			dd.Data.QueriedFromZone, dd.Data.QueriedToZone)
	}
}
