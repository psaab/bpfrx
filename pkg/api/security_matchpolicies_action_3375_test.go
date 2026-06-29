package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/policymatch"
)

// hostInboundAPIStore mirrors the gRPC hostInboundStore: a defined zone with NO
// `to-zone junos-host` policy and a default deny, so a `to-zone junos-host`
// query resolves to the host-inbound (local delivery) verdict (#3285).
func hostInboundAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// actionResponse decodes the REST /security/match envelope including the #3375
// default_used bit.
type actionResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched              bool   `json:"matched"`
		Action               string `json:"action"`
		HostInboundUnmatched bool   `json:"host_inbound_unmatched"`
		DefaultUsed          bool   `json:"default_used"`
	} `json:"data"`
}

func matchAction(t *testing.T, s *Server, q url.Values) actionResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp actionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp
}

// TestMatchPoliciesRESTActionParity3375 pins #3375 on the REST surface and
// asserts REST/gRPC agree on the host-inbound + default-used verdicts:
//
//   - host-inbound: action == policymatch.HostInboundActionString (the SSOT
//     string the gRPC surface now returns too), DefaultUsed false.
//   - default deny: action == "deny (default)" AND default_used == true (the
//     new typed bit).
//
// RED-on-revert: removing the DefaultUsed field copy in matchPoliciesHandler
// zeroes default_used and the default-deny assertion fails; reverting the SSOT
// to inline literals still passes the string (REST was already correct), but the
// gRPC parity test in pkg/grpcapi is the RED-on-revert for the gRPC half.
func TestMatchPoliciesRESTActionParity3375(t *testing.T) {
	store := hostInboundAPIStore(t)
	s := &Server{store: store}

	// host-inbound: no junos-host policy.
	hi := matchAction(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"junos-host"}})
	if !hi.Data.HostInboundUnmatched {
		t.Fatalf("host_inbound_unmatched = false, want true; got %+v", hi.Data)
	}
	if hi.Data.Action != policymatch.HostInboundActionString {
		t.Errorf("action = %q, want %q", hi.Data.Action, policymatch.HostInboundActionString)
	}
	if hi.Data.DefaultUsed {
		t.Errorf("default_used = true, want false (host path has no default fallback)")
	}

	// default deny: untrust->trust has no rule.
	dd := matchAction(t, s, url.Values{"from_zone": {"untrust"}, "to_zone": {"trust"}})
	if dd.Data.Matched {
		t.Fatalf("matched = true, want false")
	}
	if dd.Data.Action != "deny (default)" {
		t.Errorf("action = %q, want %q", dd.Data.Action, "deny (default)")
	}
	if !dd.Data.DefaultUsed {
		t.Errorf("default_used = false, want true (default-policy verdict)")
	}
}

// TestMatchPoliciesRESTNilConfigDefaultDeny pins #3375: with no active config
// the REST surface returns an explicit deny (default) with the typed
// default_used bit (parity with the gRPC nil-config path).
//
// RED-on-revert: before #3375 the nil-config branch omitted default_used, so
// the DefaultUsed assertion fails.
func TestMatchPoliciesRESTNilConfigDefaultDeny(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}
	if store.ActiveConfig() != nil {
		t.Skip("active config is not nil; nil-config path not exercised")
	}

	dd := matchAction(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}})
	if dd.Data.Action != "deny (default)" {
		t.Errorf("action = %q, want %q", dd.Data.Action, "deny (default)")
	}
	if !dd.Data.DefaultUsed {
		t.Errorf("default_used = false, want true (no-config fail-closed default deny)")
	}
}
