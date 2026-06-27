package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

type schedulerCounterAPIDP struct {
	*dataplane.Manager
	counters map[uint32]dataplane.CounterValue
}

func (d *schedulerCounterAPIDP) IsLoaded() bool {
	return true
}

func (d *schedulerCounterAPIDP) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	return d.counters[policyID], nil
}

func newSchedulerCounterAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone dmz;
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone dmz {
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone trust to-zone untrust {
            policy scheduled-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
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

func scheduledCounterPolicyID(t *testing.T, store *configstore.Store) uint32 {
	t.Helper()

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	for setID, zpp := range cfg.Security.Policies {
		for ruleIndex, pol := range zpp.Policies {
			if zpp.FromZone == "trust" && zpp.ToZone == "untrust" && pol.Name == "scheduled-allow" {
				if setID == 0 {
					t.Fatalf("scheduled policy compiled in policy set 0; test needs a nonzero policy set")
				}
				return uint32(setID)*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
			}
		}
	}
	t.Fatal("scheduled policy not found")
	return 0
}

// enablePolicyStatsAPI commits `security policy-stats system-wide
// enable` onto an existing store so the per-policy display gate (#2118)
// admits the live counters. Kept separate from newSchedulerCounterAPI
// Store so the M4 gate-off test (TestCollectPolicyCountersGatedOnPolicy
// Stats) can keep using the knob-disabled store.
func enablePolicyStatsAPI(t *testing.T, store *configstore.Store) {
	t.Helper()
	// newSchedulerCounterAPIStore leaves the store in configure mode
	// (EnterConfigure was called and Commit does not exit it), so set the
	// knob directly without re-entering configure.
	if err := store.SetFromInput("security policy-stats system-wide enable"); err != nil {
		t.Fatalf("SetFromInput(policy-stats) error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if cfg := store.ActiveConfig(); cfg == nil || !cfg.Security.PolicyStatsEnabled {
		t.Fatal("policy-stats enable did not take effect")
	}
}

func TestPoliciesHandlerExposesScheduledRuleCounters(t *testing.T) {
	store := newSchedulerCounterAPIStore(t)
	enablePolicyStatsAPI(t, store)
	policyID := scheduledCounterPolicyID(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterAPIDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				1:        {Packets: 99, Bytes: 9900},
				policyID: {Packets: 17, Bytes: 1700},
			},
		},
	}

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
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	for _, policy := range resp.Data {
		if policy.FromZone != "trust" || policy.ToZone != "untrust" {
			continue
		}
		for _, rule := range policy.Rules {
			if rule.Name != "scheduled-allow" {
				continue
			}
			if !rule.Count {
				t.Fatal("scheduled-allow Count = false, want true")
			}
			if rule.HitPackets != 17 || rule.HitBytes != 1700 {
				t.Fatalf("scheduled-allow counters = %d packets/%d bytes, want 17/1700",
					rule.HitPackets, rule.HitBytes)
			}
			return
		}
	}
	t.Fatal("scheduled-allow rule not found in API response")
}

// newPolicyCounterAPIStoreNoStats builds the same fixture as
// newSchedulerCounterAPIStore but WITHOUT `policy-stats system-wide
// enable`, so the #2118 display gate must suppress the REST counters.
func newPolicyCounterAPIStoreNoStats(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone dmz;
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone dmz {
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone trust to-zone untrust {
            policy scheduled-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
                scheduler-name workhours;
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
	if cfg := store.ActiveConfig(); cfg == nil || cfg.Security.PolicyStatsEnabled {
		t.Fatal("test precondition: policy-stats must be disabled in this store")
	}
	return store
}

// TestPoliciesHandlerGatesCountersOnPolicyStats verifies the #2118
// display gate AND the #3074 per-policy `then count` override on the REST
// `GET /api/v1/security/policies` endpoint. With `policy-stats` OFF: a
// rule WITHOUT `then count` (plain-allow) reports 0/0 (the gate), while a
// rule WITH `then count` (scheduled-allow) reports its live counts —
// `then count` opts the policy into per-policy counting independent of the
// system-wide knob. Before #3074 `then count` was inert and every rule
// read 0/0 with the knob off.
func TestPoliciesHandlerGatesCountersOnPolicyStats(t *testing.T) {
	store := newPolicyCounterAPIStoreNoStats(t)
	policyID := scheduledCounterPolicyID(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterAPIDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				// plain-allow (no then count) occupies slot 0.
				0:        {Packets: 99, Bytes: 9900},
				policyID: {Packets: 17, Bytes: 1700},
			},
		},
	}

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
		t.Fatalf("unmarshal response: %v", err)
	}
	var sawScheduled, sawPlain bool
	for _, policy := range resp.Data {
		for _, rule := range policy.Rules {
			switch rule.Name {
			case "scheduled-allow":
				sawScheduled = true
				// #3074: then count -> exposed even with the knob off.
				if rule.HitPackets != 17 || rule.HitBytes != 1700 {
					t.Fatalf("scheduled-allow (then count) counters = %d/%d, want 17/1700 (policy-stats off)",
						rule.HitPackets, rule.HitBytes)
				}
			case "plain-allow":
				sawPlain = true
				// M4/#2118 gate: no then count -> suppressed with knob off.
				if rule.HitPackets != 0 || rule.HitBytes != 0 {
					t.Fatalf("plain-allow (no then count) counters = %d/%d, want 0/0 (policy-stats off)",
						rule.HitPackets, rule.HitBytes)
				}
			}
		}
	}
	if !sawScheduled || !sawPlain {
		t.Fatalf("policies missing from response (scheduled=%v plain=%v)", sawScheduled, sawPlain)
	}
}
