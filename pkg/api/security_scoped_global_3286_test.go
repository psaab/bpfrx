package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3286: the REST GET /api/v1/security/policies inventory rendered a scoped
// global policy (#3148, `match from-zone`/`to-zone`) as all-zones, dropping
// the configured zone scope. PolicyRule now carries match_from_zone /
// match_to_zone so a scoped global shows its real scope. This is the
// fail-on-revert guard: drop the population in security.go and the scoped
// assertion goes RED.

// scopedGlobalAPIStore builds a config with one scoped global policy
// (from-zone trust, to-zone untrust) and one unscoped (all-zones) global.
func scopedGlobalAPIStore(t *testing.T) *configstore.Store {
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
        global {
            policy scoped-global {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy open-global {
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

// TestPoliciesHandlerScopedGlobalShowsZones is the #3286 fail-on-revert guard:
// the REST inventory must surface the from/to-zone of a scoped global rule and
// leave them empty (omitted) for an unscoped global.
func TestPoliciesHandlerScopedGlobalShowsZones(t *testing.T) {
	s := &Server{store: scopedGlobalAPIStore(t)}

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

	var sawScoped, sawOpen bool
	for _, policy := range resp.Data {
		// Globals stay grouped under the all-zones "*"/"*" PolicyInfo.
		if policy.FromZone != "*" || policy.ToZone != "*" {
			continue
		}
		for _, rule := range policy.Rules {
			switch rule.Name {
			case "scoped-global":
				sawScoped = true
				if rule.MatchFromZone != "trust" || rule.MatchToZone != "untrust" {
					t.Fatalf("scoped-global match zones = %q/%q, want trust/untrust "+
						"(scoped global rendered as all-zones — #3286 regression); body: %s",
						rule.MatchFromZone, rule.MatchToZone, rr.Body.String())
				}
			case "open-global":
				sawOpen = true
				if rule.MatchFromZone != "" || rule.MatchToZone != "" {
					t.Fatalf("open-global match zones = %q/%q, want empty (all-zones global)",
						rule.MatchFromZone, rule.MatchToZone)
				}
			}
		}
	}
	if !sawScoped {
		t.Fatalf("scoped-global policy missing from REST inventory; body: %s", rr.Body.String())
	}
	if !sawOpen {
		t.Fatalf("open-global policy missing from REST inventory; body: %s", rr.Body.String())
	}
}
