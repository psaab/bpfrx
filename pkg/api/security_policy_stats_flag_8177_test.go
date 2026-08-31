package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #8177 row 6: the REST policy inventory carried `count` but not the
// system-wide policy-stats knob, so "stats on, count=false" (counter read, 0
// means no traffic) and "stats off, count=false" (never read) serialized
// identically.
func newStatsFlagRESTStore(t *testing.T, statsEnabled bool) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	stanza := ""
	if statsEnabled {
		stanza = "policy-stats { system-wide enable; }"
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    ` + stanza + `
    policies {
        from-zone trust to-zone untrust {
            policy plain-allow {
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
	if got := store.ActiveConfig().Security.PolicyStatsEnabled; got != statsEnabled {
		t.Fatalf("fixture precondition: PolicyStatsEnabled = %v, want %v — the stanza did not take, "+
			"so this cell would compare two identical configs", got, statsEnabled)
	}
	return store
}

func restPolicyInfos8177(t *testing.T, s *Server) []PolicyInfo {
	t.Helper()
	rr := httptest.NewRecorder()
	s.policiesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/policies", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success || len(resp.Data) == 0 {
		t.Fatalf("no policy blocks in response; body: %s", rr.Body.String())
	}
	return resp.Data
}

// The two states must be distinguishable. Compares two RENDERINGS rather than
// reading one field, so a field wired to a literal — which looks identical when
// you only check the disabled case — fails here.
func TestRESTStatsOnAndOffAreDistinguishable_8177(t *testing.T) {
	off := restPolicyInfos8177(t, &Server{store: newStatsFlagRESTStore(t, false)})
	on := restPolicyInfos8177(t, &Server{store: newStatsFlagRESTStore(t, true)})

	for _, pi := range off {
		if pi.PolicyStatsEnabled {
			t.Errorf("zone-pair %s->%s reports policy_stats_enabled=true with the knob OFF",
				pi.FromZone, pi.ToZone)
		}
	}
	sawOn := false
	for _, pi := range on {
		if pi.PolicyStatsEnabled {
			sawOn = true
		}
	}
	if !sawOn {
		t.Error("no zone-pair reports policy_stats_enabled=true with the knob ON; the field is " +
			"constant, so a consumer still cannot tell an authoritative zero from an unmeasured one")
	}
}

// The field must actually be SERIALIZED. A Go-struct assertion passes even if
// the json tag is wrong or the field is unexported, and the consumer this issue
// is about reads JSON, not Go.
func TestRESTStatsFlagIsOnTheWire_8177(t *testing.T) {
	s := &Server{store: newStatsFlagRESTStore(t, true)}
	rr := httptest.NewRecorder()
	s.policiesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/policies", nil))

	var resp struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Data) == 0 {
		t.Fatal("no blocks")
	}
	raw, ok := resp.Data[0]["policy_stats_enabled"]
	if !ok {
		t.Fatalf("policy_stats_enabled absent from the JSON body; keys: %v", keysOf8177(resp.Data[0]))
	}
	if string(raw) != "true" {
		t.Errorf("policy_stats_enabled = %s, want true", raw)
	}
}

func keysOf8177(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
