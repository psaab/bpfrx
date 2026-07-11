package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// fragmentAPIStore builds the #5572 fixture over the REST surface: a
// source-scoped `deny junos-https` (TCP/443) before a `permit any`, so a
// non-first fragment overlapping the deny must inherit it while a plain
// omitted-port packet permits.
func fragmentAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.0.0/8;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy block-https {
                match { source-address trust-net; destination-address any; application junos-https; }
                then { deny; }
            }
            policy permit-all {
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

type fragMatchResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched                bool   `json:"matched"`
		PolicyName             string `json:"policy_name"`
		Action                 string `json:"action"`
		FragmentAssociatedDeny bool   `json:"fragment_associated_deny"`
		FragmentDenyNote       string `json:"fragment_deny_note"`
	} `json:"data"`
}

func fragMatch(t *testing.T, s *Server, q url.Values) fragMatchResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp fragMatchResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp
}

// TestMatchPoliciesRESTNonFirstFragment5572 pins the REST plumbing of the #5572
// non_first_fragment discriminator end to end: the same tuple returns PERMIT as
// a normal packet but the enforcing DENY when non_first_fragment=true.
func TestMatchPoliciesRESTNonFirstFragment5572(t *testing.T) {
	s := &Server{store: fragmentAPIStore(t)}

	base := url.Values{
		"from_zone": {"trust"}, "to_zone": {"untrust"},
		"src_ip": {"10.1.2.3"}, "dst_ip": {"203.0.113.9"},
		"protocol": {"tcp"},
	}

	// Normal (no fragment): permit via permit-all.
	normal := fragMatch(t, s, base)
	if !normal.Data.Matched || normal.Data.Action != "permit" || normal.Data.PolicyName != "permit-all" {
		t.Fatalf("normal packet must permit via permit-all; got %+v", normal.Data)
	}
	if normal.Data.FragmentAssociatedDeny {
		t.Fatalf("normal packet must not carry fragment_associated_deny; got %+v", normal.Data)
	}

	// Fragment: inherit the overlapping port-bearing deny.
	frag := url.Values{}
	for k, v := range base {
		frag[k] = v
	}
	frag.Set("non_first_fragment", "true")
	fr := fragMatch(t, s, frag)
	if !fr.Data.Matched || fr.Data.Action != "deny" || fr.Data.PolicyName != "block-https" {
		t.Fatalf("non-first fragment must inherit block-https deny; got %+v", fr.Data)
	}
	if !fr.Data.FragmentAssociatedDeny || fr.Data.FragmentDenyNote == "" {
		t.Fatalf("fragment deny must set the advisory fields; got %+v", fr.Data)
	}
}

// TestMatchPoliciesRESTNonFirstFragmentMalformed5572 pins the fail-closed parse:
// a non-canonical non_first_fragment value is a 400, never a silent
// normal-packet default on a security-verification endpoint.
func TestMatchPoliciesRESTNonFirstFragmentMalformed5572(t *testing.T) {
	s := &Server{store: fragmentAPIStore(t)}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET",
		"/api/v1/security/match?from_zone=trust&to_zone=untrust&non_first_fragment=maybe", nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 400 {
		t.Fatalf("malformed non_first_fragment must be 400; got %d, body: %s", rr.Code, rr.Body.String())
	}
}
