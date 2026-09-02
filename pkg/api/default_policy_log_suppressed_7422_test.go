package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// #7422 row 13: under a default-DENY the default-policy-log flags are INERT, so
// the synthetic default-policy row must NOT report them as live.
//
// This is the other half of #3670's cell, which now runs under permit-all where
// its property is genuinely true. Both are needed: a permit-only fixture cannot
// see the gate (the flags pass through unchanged there), and a deny-only
// fixture asserting the OLD expectation passes on the unfixed code. The pair is
// what makes either assertion mean something.
//
// The dataplane never emits session-init/session-close for a deny verdict —
// no session is installed for the records to fire on, and the deny is already
// logged by the policy-deny record (#3534, which warns about exactly this
// config). Reporting log=true here tells audit tooling the most
// security-relevant boundary is logged when nothing logs.
func TestDefaultPolicyLogSuppressedUnderDenyDefault7422(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Both log modes configured, and the default verdict left at its implicit
	// DENY — the accepted-but-inert combination.
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy-log {
            session-init;
            session-close;
        }
        from-zone trust to-zone untrust {
            policy allow-first {
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

	// PREMISE, asserted rather than assumed: the flags really are configured and
	// the default really is a deny. Without this the cell could pass because the
	// fixture stopped setting the flags at all.
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if !cfg.Security.DefaultPolicyLogSessionInit || !cfg.Security.DefaultPolicyLogSessionClose {
		t.Fatalf("fixture must set BOTH log modes: init=%v close=%v",
			cfg.Security.DefaultPolicyLogSessionInit, cfg.Security.DefaultPolicyLogSessionClose)
	}
	if cfg.Security.DefaultPolicy != 1 /* PolicyDeny */ {
		t.Fatalf("fixture must leave the default verdict at DENY, got %v", cfg.Security.DefaultPolicy)
	}

	srv := &Server{store: store}
	rr := httptest.NewRecorder()
	srv.policiesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/policies", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data []struct {
			FromZone string `json:"from_zone"`
			Rules    []struct {
				Name            string `json:"name"`
				Log             bool   `json:"log"`
				LogSessionInit  bool   `json:"log_session_init"`
				LogSessionClose bool   `json:"log_session_close"`
			} `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body: %s", err, rr.Body.String())
	}

	found := false
	for _, set := range resp.Data {
		for _, r := range set.Rules {
			if !strings.Contains(r.Name, "default-policy") {
				continue
			}
			found = true
			if r.Log || r.LogSessionInit || r.LogSessionClose {
				t.Fatalf("under a default-DENY the log flags are inert and must not be "+
					"reported live; got log=%v init=%v close=%v. The dataplane emits no "+
					"session-init/close record for a verdict that installs no session "+
					"(#3534), so this tells audit tooling the boundary is logged when "+
					"nothing logs.", r.Log, r.LogSessionInit, r.LogSessionClose)
			}
		}
	}
	if !found {
		t.Fatal("no default-policy row in the response — the assertion above would " +
			"have been vacuous")
	}
}
