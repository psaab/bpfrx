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

// #3623: the REST security-policy inventory and the /security/match diagnostic
// serialized the runtime policy_id with a zero-value-omitting encoding
// (`omitempty` on a plain uint32), so the FIRST runtime policy — which
// legitimately has policy_id 0 (policySetID*MaxRulesPerPolicy + ruleIndex =
// 0*256 + 0) — was dropped from the wire. Since #3057 the implicit default
// policy uses a distinct sentinel (0xFFFFFFFF), so id 0 is UNAMBIGUOUSLY a real
// policy; a consumer joining an RT_FLOW event (policy_id=0) back to the
// inventory then found no matching row.
//
// The fix drops omitempty on the inventory PolicyRule.PolicyID (always present)
// and makes MatchPoliciesResult.PolicyID a *uint32 (present only on a match,
// emitted even at 0). These tests assert the RAW JSON carries "policy_id":0 for
// the first rule / first-rule match. RED-on-revert: restore omitempty (or the
// plain-uint32 match field) and the key-presence assertions below fail.

// firstPolicyZeroAPIStore commits a single zone-pair policy whose sole rule is
// the first runtime policy — its span-accumulated runtime id is 0.
func firstPolicyZeroAPIStore(t *testing.T) *configstore.Store {
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

func TestPoliciesHandlerEmitsPolicyIDZeroForFirstRule(t *testing.T) {
	store := firstPolicyZeroAPIStore(t)
	s := &Server{store: store}

	// Sanity: the first policy's runtime id really is 0 (the id-0 edge #3623
	// targets). If this ever changes the test would silently pass a non-edge.
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)
	if got := dpuserspace.RuntimePolicyIndex(ids, 0, 0); got != 0 {
		t.Fatalf("first policy runtime id = %d, want 0 (fixture no longer exercises the id-0 edge)", got)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// Raw decode so an OMITTED zero is distinguishable from a present 0.
	var raw struct {
		Data []struct {
			Rules []map[string]json.RawMessage `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v; body: %s", err, rr.Body.String())
	}

	var found bool
	for _, pi := range raw.Data {
		for _, r := range pi.Rules {
			name := ""
			_ = json.Unmarshal(r["name"], &name)
			if name != "allow-first" {
				continue
			}
			found = true
			pidRaw, ok := r["policy_id"]
			if !ok {
				t.Fatalf("allow-first row omitted policy_id for id 0 (#3623 regression: "+
					"the first policy's join key is dropped); body: %s", rr.Body.String())
			}
			var pid uint32
			if err := json.Unmarshal(pidRaw, &pid); err != nil {
				t.Fatalf("policy_id not numeric: %v (raw %s)", err, string(pidRaw))
			}
			if pid != 0 {
				t.Fatalf("allow-first policy_id = %d, want 0", pid)
			}
		}
	}
	if !found {
		t.Fatalf("allow-first missing from REST inventory; body: %s", rr.Body.String())
	}
}

func TestMatchPoliciesHandlerEmitsPolicyIDZeroForFirstRule(t *testing.T) {
	store := firstPolicyZeroAPIStore(t)
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	q := url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}}
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// Raw decode of the envelope's data object.
	var raw struct {
		Success bool                       `json:"success"`
		Data    map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v; body: %s", err, rr.Body.String())
	}
	if !raw.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	var matched bool
	_ = json.Unmarshal(raw.Data["matched"], &matched)
	if !matched {
		t.Fatalf("expected a match for trust->untrust; body: %s", rr.Body.String())
	}
	pidRaw, ok := raw.Data["policy_id"]
	if !ok {
		t.Fatalf("match-policies omitted policy_id for the matched first policy (id 0) — "+
			"#3623 regression: a matched-first-policy answer looks unmatched; body: %s", rr.Body.String())
	}
	var pid uint32
	if err := json.Unmarshal(pidRaw, &pid); err != nil {
		t.Fatalf("policy_id not numeric: %v (raw %s)", err, string(pidRaw))
	}
	if pid != 0 {
		t.Fatalf("matched policy_id = %d, want 0 (first policy); body: %s", pid, rr.Body.String())
	}
}

// TestMatchPoliciesHandlerOmitsPolicyIDWhenUnmatched pins the OTHER half of the
// pointer contract: an unmatched answer must NOT emit policy_id (nil pointer),
// so a client never mistakes an unmatched verdict for "matched policy 0". With
// the fix reverted to a plain uint32 (no omitempty) this would emit
// "policy_id":0 and the presence check below would fail.
func TestMatchPoliciesHandlerOmitsPolicyIDWhenUnmatched(t *testing.T) {
	store := firstPolicyZeroAPIStore(t)
	s := &Server{store: store}

	// untrust->trust has no rule -> default-policy deny, no matched policy id.
	rr := httptest.NewRecorder()
	q := url.Values{"from_zone": {"untrust"}, "to_zone": {"trust"}}
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var raw struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v; body: %s", err, rr.Body.String())
	}
	var matched bool
	_ = json.Unmarshal(raw.Data["matched"], &matched)
	if matched {
		t.Fatalf("expected NO match for untrust->trust; body: %s", rr.Body.String())
	}
	if _, ok := raw.Data["policy_id"]; ok {
		t.Fatalf("unmatched response emitted policy_id; want it omitted (would look like matched policy 0); body: %s",
			rr.Body.String())
	}
}
