package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// scopeIDAPIStore mirrors the gRPC TestMatchPoliciesResponseCarriesScopeAndID
// fixture: two zone pairs sharing the duplicate policy NAME "allow" (legal in
// Junos) plus a scoped global policy, so a name-only verdict is ambiguous —
// exactly the #3331 case.
func scopeIDAPIStore(t *testing.T) *configstore.Store {
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
        from-zone untrust to-zone trust {
            policy allow {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        global {
            policy g-allow {
                match { source-address any; destination-address any; application any; from-zone trust; }
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

// scopeIDResponse decodes the REST /security/match envelope including the
// #3331 scope/id fields.
type scopeIDResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched    bool   `json:"matched"`
		PolicyName string `json:"policy_name"`
		Global     bool   `json:"global"`
		FromZone   string `json:"from_zone"`
		ToZone     string `json:"to_zone"`
		PolicyID   uint32 `json:"policy_id"`
	} `json:"data"`
}

func matchScopeID(t *testing.T, s *Server, q url.Values) scopeIDResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp scopeIDResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp
}

// TestMatchPoliciesRESTCarriesScopeAndID pins #3331 on the REST surface: the
// /security/match JSON must carry the matched policy's global/from_zone/to_zone/
// policy_id so a caller can disambiguate a verdict when policy names collide
// across zone pairs / global scope.
//
// RED-on-revert: removing the global/from_zone/to_zone/policy_id field copies in
// matchPoliciesHandler (pkg/api/security.go) zeroes every field below and every
// assertion fails. The matcher + gRPC tests pin those layers; this pins the REST
// mapping the gRPC/CLI tests do NOT exercise.
func TestMatchPoliciesRESTCarriesScopeAndID(t *testing.T) {
	store := scopeIDAPIStore(t)
	s := &Server{store: store}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)

	// untrust->trust "allow" (deny) — a zone-pair match.
	resp := matchScopeID(t, s, url.Values{"from_zone": {"untrust"}, "to_zone": {"trust"}})
	if !resp.Data.Matched {
		t.Fatalf("expected match; got %+v", resp.Data)
	}
	if resp.Data.Global {
		t.Errorf("global = true, want false (zone-pair policy)")
	}
	if resp.Data.FromZone != "untrust" || resp.Data.ToZone != "trust" {
		t.Errorf("scope = %s->%s, want untrust->trust", resp.Data.FromZone, resp.Data.ToZone)
	}
	if resp.Data.PolicyName != "allow" {
		t.Errorf("policy_name = %q, want allow", resp.Data.PolicyName)
	}
	var untrustSet, trustSet int
	for i, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		if zpp.FromZone == "untrust" && zpp.ToZone == "trust" {
			untrustSet = i
		}
		if zpp.FromZone == "trust" && zpp.ToZone == "untrust" {
			trustSet = i
		}
	}
	wantID := ids[[2]uint32{uint32(untrustSet), 0}]
	if resp.Data.PolicyID != wantID {
		t.Errorf("policy_id = %d, want %d (untrust->trust runtime ID)", resp.Data.PolicyID, wantID)
	}
	if otherID := ids[[2]uint32{uint32(trustSet), 0}]; otherID == resp.Data.PolicyID {
		t.Errorf("duplicate-name policies share policy_id %d; cannot disambiguate", resp.Data.PolicyID)
	}

	// trust->trust has no exact zone-pair rule, so the scoped global g-allow
	// wins — proving the global branch's scope/id flows through REST too.
	gp := matchScopeID(t, s, url.Values{"from_zone": {"trust"}, "to_zone": {"trust"}})
	if !gp.Data.Matched || !gp.Data.Global {
		t.Fatalf("expected scoped-global match for trust->trust; got %+v", gp.Data)
	}
	if gp.Data.PolicyName != "g-allow" {
		t.Errorf("policy_name = %q, want g-allow", gp.Data.PolicyName)
	}
	if gp.Data.FromZone != "trust" {
		t.Errorf("global scope from_zone = %q, want trust", gp.Data.FromZone)
	}
	wantGID := ids[[2]uint32{uint32(len(cfg.Security.Policies)), 0}]
	if gp.Data.PolicyID != wantGID {
		t.Errorf("policy_id = %d, want %d (global set runtime ID)", gp.Data.PolicyID, wantGID)
	}
}
