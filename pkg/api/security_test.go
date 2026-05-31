package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// matchPoliciesAPIStore builds a config with a single trust->untrust
// policy whose terms reference a restricted address-book entry (not
// "any"), exercising the actual #1711 false-positive shape in the REST
// simulator handler.
func matchPoliciesAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
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

// TestMatchPoliciesHandlerValidation covers the REST simulator handler
// (GET /api/v1/security/match): a non-empty malformed src_ip/dst_ip must
// return 400 rather than silently wildcard-matching, while empty/valid
// inputs succeed (#1711).
func TestMatchPoliciesHandlerValidation(t *testing.T) {
	s := &Server{store: matchPoliciesAPIStore(t)}

	tests := []struct {
		name      string
		query     url.Values
		wantCode  int
		wantMatch bool // for 200 cases: must data.matched be true?
	}{
		{
			name:     "invalid src_ip",
			query:    url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}, "src_ip": {"10.0.0.999"}},
			wantCode: 400,
		},
		{
			name:     "invalid dst_ip",
			query:    url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}, "dst_ip": {"garbage"}},
			wantCode: 400,
		},
		{
			name:     "cidr in ip field rejected",
			query:    url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}, "src_ip": {"10.0.0.0/24"}},
			wantCode: 400,
		},
		{
			name:      "empty ips match any",
			query:     url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}},
			wantCode:  200,
			wantMatch: true,
		},
		{
			name:      "valid in-term ip",
			query:     url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}, "src_ip": {"10.0.1.5"}, "dst_ip": {"10.0.1.6"}},
			wantCode:  200,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/v1/security/match?"+tt.query.Encode(), nil)
			s.matchPoliciesHandler(rr, req)

			if rr.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body: %s", rr.Code, tt.wantCode, rr.Body.String())
			}

			var resp struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
				Data    struct {
					Matched    bool   `json:"matched"`
					PolicyName string `json:"policy_name"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v; body: %s", err, rr.Body.String())
			}
			if tt.wantCode == 400 {
				if resp.Success {
					t.Fatalf("success = true on 400; body: %s", rr.Body.String())
				}
				if resp.Error == "" {
					t.Fatalf("error message empty on 400; body: %s", rr.Body.String())
				}
				return
			}
			if !resp.Success {
				t.Fatalf("success = false on 200; body: %s", rr.Body.String())
			}
			// Assert the actual verdict, not just the envelope — a silent
			// default-deny would otherwise pass the 200 cases.
			gotMatch := resp.Data.Matched && resp.Data.PolicyName == "restricted-allow"
			if gotMatch != tt.wantMatch {
				t.Fatalf("matched=%v policy=%q, want match=%v; body: %s",
					resp.Data.Matched, resp.Data.PolicyName, tt.wantMatch, rr.Body.String())
			}
		})
	}
}
