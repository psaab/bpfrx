package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3670: the implicit default-policy carries its own RT_FLOW log intent
// (default-policy-log session-init | session-close, compiled to
// Security.DefaultPolicyLogSessionInit/Close and threaded to the dataplane via
// ConfigSnapshot.DefaultLogSessionInit/Close in the #3534 builder). The REST
// /security/policies inventory synthesizes a "-"/"-" default-policy catch-all
// row, but that row omitted the log state — so audit tooling read the
// most security-relevant boundary as UNLOGGED while the dataplane was emitting
// default-verdict session-init/close records.
//
// This test commits a default-policy with both log modes and asserts the
// synthetic row exposes log / log_session_init / log_session_close. RED-on-
// revert: drop the log-field population on the defRule and the assertions below
// fail (log false, the two omitempty session-mode keys absent).

func defaultPolicyLogAPIStore(t *testing.T) *configstore.Store {
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
        // #7422 row 13: the default verdict is now PERMIT-ALL, and that is
        // load-bearing rather than incidental. The session-init/session-close
        // records fire only for a default-PERMIT (the only verdict that
        // installs a session), so under the previous implicit deny-all these
        // flags were accepted-but-inert (#3534) and the row below asserted a
        // log posture the dataplane never enforced. #3670's property — audit
        // tooling must not read the boundary as unlogged while the dataplane
        // IS emitting — is preserved exactly, on the config where it is true.
        // The deny-all suppression is covered by
        // TestDefaultPolicyLogSuppressedUnderDenyDefault7422.
        default-policy {
            permit-all;
        }
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
	return store
}

func TestPoliciesHandlerDefaultPolicyRowExposesLogState(t *testing.T) {
	store := defaultPolicyLogAPIStore(t)

	// Sanity: the compiled config really carries both default-policy log modes;
	// otherwise the test would silently pass without exercising the edge.
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if !cfg.Security.DefaultPolicyLogSessionInit || !cfg.Security.DefaultPolicyLogSessionClose {
		t.Fatalf("fixture no longer sets both default-policy log modes: init=%v close=%v",
			cfg.Security.DefaultPolicyLogSessionInit, cfg.Security.DefaultPolicyLogSessionClose)
	}

	s := &Server{store: store}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// Raw decode so an OMITTED omitempty session-mode key is distinguishable
	// from a present-but-false one.
	var raw struct {
		Data []struct {
			Rules []map[string]json.RawMessage `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v; body: %s", err, rr.Body.String())
	}

	var defRow map[string]json.RawMessage
	for _, pi := range raw.Data {
		for _, r := range pi.Rules {
			name := ""
			_ = json.Unmarshal(r["name"], &name)
			if name == dataplane.DefaultPolicyName {
				defRow = r
			}
		}
	}
	if defRow == nil {
		t.Fatalf("REST inventory missing synthetic default-policy row (name=%q); body: %s",
			dataplane.DefaultPolicyName, rr.Body.String())
	}

	// The collapsed `log` bool is always present (no omitempty); it must be true
	// because at least one session-mode log is requested.
	var logBool bool
	if err := json.Unmarshal(defRow["log"], &logBool); err != nil {
		t.Fatalf("default-policy row `log` not decodable: %v (raw %s)", err, string(defRow["log"]))
	}
	if !logBool {
		t.Fatalf("default-policy row log=false, want true (#3670 regression: the "+
			"synthetic row does not reflect the configured default-policy-log intent); body: %s",
			rr.Body.String())
	}

	// The independent session-init / session-close modes must be present and
	// true. With the fix reverted these omitempty keys are absent.
	for _, key := range []string{"log_session_init", "log_session_close"} {
		rawv, ok := defRow[key]
		if !ok {
			t.Fatalf("default-policy row omitted %q (#3670 regression: default-policy "+
				"log mode not surfaced); body: %s", key, rr.Body.String())
		}
		var v bool
		if err := json.Unmarshal(rawv, &v); err != nil {
			t.Fatalf("default-policy row %q not decodable: %v (raw %s)", key, err, string(rawv))
		}
		if !v {
			t.Fatalf("default-policy row %q = false, want true", key)
		}
	}
}
