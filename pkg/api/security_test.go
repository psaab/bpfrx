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

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
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
			// #3355 (H06): a missing from_zone must be rejected for parity with
			// the CLI, not evaluated as the empty-string zone.
			name:     "missing from_zone",
			query:    url.Values{"to_zone": {"untrust"}, "src_ip": {"10.0.1.5"}},
			wantCode: 400,
		},
		{
			name:     "missing to_zone",
			query:    url.Values{"from_zone": {"trust"}, "src_ip": {"10.0.1.5"}},
			wantCode: 400,
		},
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

// globalPolicyAPIStore builds a config with one zone-pair policy plus one
// global policy so the REST /security/policies enumeration must surface
// both surfaces (#3045).
func globalPolicyAPIStore(t *testing.T) *configstore.Store {
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
        from-zone trust to-zone untrust {
            policy zone-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy global-deny {
                match { source-address any; destination-address any; application any; }
                then { deny; }
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

// TestPoliciesHandlerIncludesGlobalPolicies is the fail-on-revert guard
// for #3045: the REST GET /api/v1/security/policies inventory must
// include configured global policies (from_zone="*"/to_zone="*"),
// matching the CLI, gRPC GetPolicies, and the Prometheus collector. If
// the handler reverts to looping zone-pair policies only, the global row
// is absent and this test goes RED.
func TestPoliciesHandlerIncludesGlobalPolicies(t *testing.T) {
	s := &Server{store: globalPolicyAPIStore(t)}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	var sawZonePair, sawGlobal bool
	for _, policy := range resp.Data {
		if policy.FromZone == "trust" && policy.ToZone == "untrust" {
			for _, rule := range policy.Rules {
				if rule.Name == "zone-allow" {
					sawZonePair = true
				}
			}
		}
		if policy.FromZone == "*" && policy.ToZone == "*" {
			for _, rule := range policy.Rules {
				if rule.Name == "global-deny" {
					if rule.Action != "deny" {
						t.Fatalf("global-deny action = %q, want deny", rule.Action)
					}
					sawGlobal = true
				}
			}
		}
	}
	if !sawZonePair {
		t.Fatal("zone-pair policy zone-allow missing from REST response (regression)")
	}
	if !sawGlobal {
		t.Fatalf("global policy global-deny missing from REST /security/policies response; "+
			"globals omitted (#3045 regression); body: %s", rr.Body.String())
	}
}
