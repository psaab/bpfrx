package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #3624: the REST security policy inventory (policiesHandler) dropped a policy's
// scheduler binding (scheduler-name) and its runtime scheduler state. #3062
// exposed both only on the human-readable TEXT policy-detail surface, so a
// structured audit client reading /security/policies could not tell that a
// permit/deny rule is time-gated, nor that it is currently runtime-inactive —
// it displayed a dormant rule as an active allow/deny. PolicyRule now carries
// scheduler_name + inactive, populated for zone-pair AND global policies from
// the same #3062 provider (Server.policySchedActiveFn). These are the
// fail-on-revert guards: drop the population in security.go and the assertions
// below go RED.

// schedInventoryAPIStore builds a config with a scheduled zone-pair permit
// (bound to "workhours"), a plain always-on zone-pair permit, and a scheduled
// global permit (also "workhours").
func schedInventoryAPIStore(t *testing.T) *configstore.Store {
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
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy sched-off {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name workhours;
            }
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy g-sched-off {
                match { source-address any; destination-address any; application any; }
                then { permit; }
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

// restInventoryRules issues GET /security/policies against s and returns the
// rules indexed by name plus the raw per-rule JSON objects (for the omitempty
// contract check).
func restInventoryRules(t *testing.T, s *Server) (map[string]PolicyRule, map[string]map[string]json.RawMessage) {
	t.Helper()
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
	rules := map[string]PolicyRule{}
	for _, pi := range resp.Data {
		for _, r := range pi.Rules {
			rules[r.Name] = r
		}
	}
	var raw struct {
		Data []struct {
			Rules []map[string]json.RawMessage `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw response: %v", err)
	}
	rawByName := map[string]map[string]json.RawMessage{}
	for _, pi := range raw.Data {
		for _, r := range pi.Rules {
			name := ""
			_ = json.Unmarshal(r["name"], &name)
			rawByName[name] = r
		}
	}
	return rules, rawByName
}

func TestPoliciesHandlerExposesSchedulerBindingAndInactiveState(t *testing.T) {
	store := schedInventoryAPIStore(t)

	// Case A: live scheduler state present and the scheduler is INACTIVE. The
	// scheduled zone-pair AND global rules must report their binding and be
	// marked inactive; the plain rule stays active with no binding.
	t.Run("scheduler inactive -> scheduler_name + inactive=true", func(t *testing.T) {
		s := &Server{store: store}
		s.policySchedActiveFn = func() (map[string]bool, bool) {
			return map[string]bool{"workhours": false}, true
		}
		rules, raw := restInventoryRules(t, s)

		so, ok := rules["sched-off"]
		if !ok {
			t.Fatalf("sched-off missing from REST inventory")
		}
		if so.SchedulerName != "workhours" {
			t.Fatalf("sched-off scheduler_name = %q, want %q (REST dropped the scheduler binding — #3624 regression)",
				so.SchedulerName, "workhours")
		}
		if !so.Inactive {
			t.Fatalf("sched-off inactive = false, want true (scheduler inactive; REST dropped runtime state — #3624 regression)")
		}

		gso, ok := rules["g-sched-off"]
		if !ok {
			t.Fatalf("g-sched-off missing from REST inventory")
		}
		if gso.SchedulerName != "workhours" || !gso.Inactive {
			t.Fatalf("g-sched-off scheduler_name=%q inactive=%v, want workhours/true (global path not plumbed — #3624)",
				gso.SchedulerName, gso.Inactive)
		}

		pl, ok := rules["plain-allow"]
		if !ok {
			t.Fatalf("plain-allow missing from REST inventory")
		}
		if pl.SchedulerName != "" || pl.Inactive {
			t.Fatalf("plain-allow scheduler_name=%q inactive=%v, want empty/false (unscheduled rule must not gain state)",
				pl.SchedulerName, pl.Inactive)
		}

		// omitempty contract: the unscheduled rule must serialize neither key.
		for _, k := range []string{"scheduler_name", "inactive"} {
			if _, present := raw["plain-allow"][k]; present {
				t.Fatalf("plain-allow serialized %q for an unset field; want omitted", k)
			}
		}
		// The inactive scheduled rule must serialize both keys.
		if _, present := raw["sched-off"]["scheduler_name"]; !present {
			t.Fatalf("sched-off did not serialize scheduler_name")
		}
		if _, present := raw["sched-off"]["inactive"]; !present {
			t.Fatalf("sched-off did not serialize inactive (true value must not be omitted)")
		}
	})

	// Case B (positive control): scheduler ACTIVE -> binding still reported,
	// inactive=false (omitted). Guards against over-marking every scheduled
	// rule inactive.
	t.Run("scheduler active -> scheduler_name kept, inactive=false", func(t *testing.T) {
		s := &Server{store: store}
		s.policySchedActiveFn = func() (map[string]bool, bool) {
			return map[string]bool{"workhours": true}, true
		}
		rules, raw := restInventoryRules(t, s)
		so := rules["sched-off"]
		if so.SchedulerName != "workhours" {
			t.Fatalf("sched-off scheduler_name = %q, want %q", so.SchedulerName, "workhours")
		}
		if so.Inactive {
			t.Fatalf("sched-off inactive = true, want false (scheduler active)")
		}
		if _, present := raw["sched-off"]["inactive"]; present {
			t.Fatalf("sched-off serialized inactive=false; want omitted (omitempty)")
		}
	})

	// Case C (fail-open display): no live state (accessor not wired) -> the
	// binding is still reported (config-derived) but inactive stays false,
	// matching the #3062 text surface's fail-open display (State: enabled) and
	// keeping the output bit-identical for existing consumers.
	t.Run("state unavailable -> scheduler_name kept, inactive=false", func(t *testing.T) {
		s := &Server{store: store}
		rules := map[string]PolicyRule{}
		got, _ := restInventoryRules(t, s)
		for k, v := range got {
			rules[k] = v
		}
		so := rules["sched-off"]
		if so.SchedulerName != "workhours" {
			t.Fatalf("sched-off scheduler_name = %q, want %q (binding is config-derived, always reported)",
				so.SchedulerName, "workhours")
		}
		if so.Inactive {
			t.Fatalf("sched-off inactive = true, want false (state unavailable must fail open on the DISPLAY surface)")
		}
	})
}
