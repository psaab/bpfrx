package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3474: the REST zone-pair per-policy counter read handle must use the RAW
// slice index i, not len(pi.Rules) (the compacted, nil-skipped running count).
// The resolver (pkg/dataplane/userspace policyRuleIDForCounter) and every other
// counter caller (metrics_counters.go policyCounterID(policySetID, i),
// cli_show_security*.go, server_show_policies_text.go, AND this handler's own
// global-policy loop) key off the raw slice index. policiesHandler was the lone
// divergent consumer using the compacted count.
//
// Nil rules are not reachable via any production config path today (strict and
// tolerant compile share a non-nil-only builder; HA ships recompiled text;
// persistence round-trips the tree), so this is defensive SSOT-alignment, the
// same posture as the #3476/#3494 nil-guards — but with a LEADING nil rule the
// compacted count lags the slice index by one and the handle drifts.
//
// Fixture: a single zone-pair set trust->untrust with a LEADING nil rule before
// the real rule p1, so p1 sits at slice index 1 (policy set 0). The raw-index
// handle is therefore 0*MaxRulesPerPolicy+1 == 1; the compacted handle (the bug)
// is 0*MaxRulesPerPolicy+0 == 0 because pi.Rules is still empty when p1 is read.
// We stock distinct counters at both handles and assert the handler reads the
// raw-index one.
//
// Fail-on-revert: restoring `uint32(len(pi.Rules))` makes the handler read
// counters[0] (88/8800) instead of counters[1] (42/4200) -> RED.
func TestPoliciesHandlerCounterHandleUsesRawSliceIndex(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    policy-stats {
        system-wide enable;
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
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

	// Inject a LEADING nil rule BEFORE p1 (the strict compiler never emits this;
	// the tolerant/HA-sync path can). Must run AFTER Commit, which recompiles and
	// would normalize the nil away. p1 now lives at slice index 1.
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.Policies) == 0 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("fixture: unexpected ActiveConfig shape: %+v", cfg)
	}
	cfg.Security.Policies[0].Policies = append([]*config.Policy{nil}, cfg.Security.Policies[0].Policies...)

	const max = dataplane.MaxRulesPerPolicy
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			0*max + 1: {Packets: 42, Bytes: 4200}, // raw slice index of p1 (correct)
			0*max + 0: {Packets: 88, Bytes: 8800}, // compacted index (the bug)
		},
	}
	s := &Server{store: store, dp: dp}

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
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}

	var p1 *PolicyRule
	for i := range resp.Data {
		for j := range resp.Data[i].Rules {
			if resp.Data[i].Rules[j].Name == "p1" {
				p1 = &resp.Data[i].Rules[j]
			}
		}
	}
	if p1 == nil {
		t.Fatalf("p1 not found in REST inventory; body: %s", rr.Body.String())
	}
	if p1.HitPackets != 42 || p1.HitBytes != 4200 {
		t.Fatalf("p1 hit counter = %d/%d, want 42/4200 (raw slice index handle 1), NOT 88/8800 (compacted handle 0)",
			p1.HitPackets, p1.HitBytes)
	}
}
