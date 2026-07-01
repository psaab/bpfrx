package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// descSchedAPIStore commits a trust->untrust PERMIT that carries BOTH a
// `description` (ticket/change context, #3685 M05) and a `scheduler-name`
// binding (#3685 M06), with default-policy deny. The scheduler "workhours"
// is defined so the config compiles cleanly.
func descSchedAPIStore(t *testing.T) *configstore.Store {
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
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-web {
                description "CHG-4242 web access";
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

// descSchedResponse decodes the REST /security/match envelope including the
// #3685 description + scheduler binding/effective-state fields.
type descSchedResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Matched         bool   `json:"matched"`
		PolicyName      string `json:"policy_name"`
		Description     string `json:"description"`
		SchedulerName   string `json:"scheduler_name"`
		SchedulerActive bool   `json:"scheduler_active"`
	} `json:"data"`
}

// TestMatchPoliciesRESTCarriesDescriptionAndScheduler pins #3685 M05+M06 on the
// REST surface: the /security/match JSON for a matched policy must carry the
// policy `description` (M05) and the scheduler binding + effective-active flag
// (M06), so a stored match verdict is not weaker than the inventory / local CLI
// answer over the same policymatch.Result.
//
// RED-on-revert: removing the Description / SchedulerName / SchedulerActive
// field copies from matchPoliciesHandler (pkg/api/security.go) drops them from
// the JSON and every assertion below fails. Removing the SchedulerName copy in
// policymatch.matchedResult also flips SchedulerName/SchedulerActive red (the
// handler derives both from res.SchedulerName).
func TestMatchPoliciesRESTCarriesDescriptionAndScheduler(t *testing.T) {
	store := descSchedAPIStore(t)
	s := &Server{store: store}
	// The scheduler must be ACTIVE for the scheduled permit to match (the
	// handler always threads a fail-closed PolicyInactiveFn, so a scheduled
	// rule is skipped unless live active-state says otherwise).
	s.policySchedActiveFn = func() (map[string]bool, bool) {
		return map[string]bool{"workhours": true}, true
	}

	rr := httptest.NewRecorder()
	q := url.Values{
		"from_zone": {"trust"},
		"to_zone":   {"untrust"},
		"protocol":  {"tcp"},
		"dst_port":  {"80"},
	}
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp descSchedResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success || !resp.Data.Matched {
		t.Fatalf("expected a successful match; body: %s", rr.Body.String())
	}
	if resp.Data.Description != "CHG-4242 web access" {
		t.Errorf("description = %q, want %q (M05); body: %s", resp.Data.Description, "CHG-4242 web access", rr.Body.String())
	}
	if resp.Data.SchedulerName != "workhours" {
		t.Errorf("scheduler_name = %q, want %q (M06); body: %s", resp.Data.SchedulerName, "workhours", rr.Body.String())
	}
	if !resp.Data.SchedulerActive {
		t.Errorf("scheduler_active = false, want true (M06 — a matched scheduled policy is currently active); body: %s", rr.Body.String())
	}
}

// TestMatchPoliciesRESTNonScheduledOmitsSchedulerFields is the negative
// control: a matched policy with NO description and NO scheduler binding must
// leave description / scheduler_name / scheduler_active omitted (all zero), so
// the new fields never manufacture a phantom time-gate for an always-on policy.
func TestMatchPoliciesRESTNonScheduledOmitsSchedulerFields(t *testing.T) {
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
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	q := url.Values{"from_zone": {"trust"}, "to_zone": {"untrust"}, "protocol": {"tcp"}, "dst_port": {"80"}}
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp descSchedResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Data.Matched {
		t.Fatalf("expected a match; body: %s", rr.Body.String())
	}
	if resp.Data.Description != "" || resp.Data.SchedulerName != "" || resp.Data.SchedulerActive {
		t.Errorf("non-scheduled/undescribed match leaked fields: description=%q scheduler_name=%q scheduler_active=%v",
			resp.Data.Description, resp.Data.SchedulerName, resp.Data.SchedulerActive)
	}
}
