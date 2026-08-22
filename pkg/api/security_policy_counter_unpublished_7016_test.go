// #7016: the REST policy inventory must not answer HTTP 500 for the WHOLE
// response because one policy's counter has not been published by the helper
// yet.
//
// #6743 activated the #3965 bulk policy-counter path on all seven observability
// call sites for the first time. The bulk reader signals an unpublished per-rule
// counter with ErrPolicyCounterUnpublished, and policiesHandler folded that into
// readErr -> 500, discarding the entire inventory. The condition is reachable
// whenever a counter-eligible policy exists (`then count`, or system-wide
// `policy-stats`) and the helper has not published that rule id: the window
// before the first 1 Hz status poll lands (the shim is loaded, so IsLoaded() is
// already true), or config skew after a non-abort-class apply failure (#5679).
//
// The disposition is the one the ZONE half of this same handler already uses for
// dataplane.ErrCounterNotPopulated (#6843): flag the affected item and serve the
// response. hit_counters_unavailable (#5580) is exactly that signal for a rule.
//
// FAIL-ON-REVERT: restoring `} else if readErr == nil { readErr = err }` at any
// of the three read sites makes the handler 500 again and the 200 assertions go
// RED. A genuine snapshot read FAILURE must still 500 — the control below.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// warmupPolicyAPIDP is LOADED but its bulk snapshot is EMPTY — the measured
// state of the real userspace Manager before the first status poll (pinned in
// pkg/dataplane/userspace TestWarmUpBulkSnapshotIsEmptyAndReadsUnpublished).
// The per-policy fallback panics: the adapter provides the bulk probe in
// production, so a fallback call here would mean the test is exercising a
// different path than the daemon does.
type warmupPolicyAPIDP struct {
	*dataplane.Manager
}

func (d *warmupPolicyAPIDP) IsLoaded() bool { return true }

func (d *warmupPolicyAPIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return map[uint32]dataplane.CounterValue{}, nil
}

func (d *warmupPolicyAPIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	panic("per-policy fallback must not run: the bulk probe resolves")
}

// bulkFailPolicyAPIDP is LOADED and its bulk snapshot read genuinely FAILS.
// That is a degraded counter bridge, not a no-data window, and must stay
// fail-loud (#3408).
type bulkFailPolicyAPIDP struct {
	*dataplane.Manager
}

func (d *bulkFailPolicyAPIDP) IsLoaded() bool { return true }

func (d *bulkFailPolicyAPIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	return nil, errors.New("counter bridge degraded")
}

func (d *bulkFailPolicyAPIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	panic("per-policy fallback must not run: the bulk probe resolves")
}

// newUnpublishedPolicyAPIStore commits a config that exercises all THREE read
// sites in policiesHandler: a zone-pair rule, a global rule, and the implicit
// default-policy row. policy-stats is on system-wide, so every row is
// counter-eligible.
func newUnpublishedPolicyAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
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
            policy zone-pair-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy global-allow {
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
	cfg := store.ActiveConfig()
	if cfg == nil || !cfg.Security.PolicyStatsEnabled {
		t.Fatal("policy-stats precondition not met")
	}
	if len(cfg.Security.GlobalPolicies) == 0 {
		t.Fatal("global policy precondition not met: the global read site would not be exercised")
	}
	return store
}

func TestPoliciesHandlerUnpublishedCounterIsNotAServerError(t *testing.T) {
	s := &Server{
		store: newUnpublishedPolicyAPIStore(t),
		dp:    &warmupPolicyAPIDP{Manager: dataplane.New()},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: an unpublished per-rule counter is a no-data window, not a request failure (#7016). body=%s",
			rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// All three read sites: zone-pair rule, global rule, default-policy row.
	for _, name := range []string{"zone-pair-allow", "global-allow", dataplane.DefaultPolicyName} {
		rule, ok := findRule(resp.Data, name)
		if !ok {
			t.Fatalf("%s missing from the inventory", name)
		}
		if !rule.HitCountersUnavailable {
			t.Errorf("%s: hit_counters_unavailable = false, want true — the counter is unpublished, so 0/0 is not authoritative", name)
		}
		if rule.HitPackets != 0 || rule.HitBytes != 0 {
			t.Errorf("%s: counters = %d/%d, want 0/0 alongside the unavailable flag", name, rule.HitPackets, rule.HitBytes)
		}
	}
}

// CONTROL: a genuine bulk-snapshot read failure is NOT the unpublished signal
// and must still fail loud as HTTP 500 (#3408). Without this, "return 200"
// could be satisfied by swallowing every counter error.
func TestPoliciesHandlerStillFailsLoudOnGenuineReadError(t *testing.T) {
	s := &Server{
		store: newUnpublishedPolicyAPIStore(t),
		dp:    &bulkFailPolicyAPIDP{Manager: dataplane.New()},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on a genuine counter-bridge failure (#3408); the #7016 relaxation must apply ONLY to the unpublished signal. body=%s",
			rr.Code, rr.Body.String())
	}
}

// #7016 (Prometheus): an unpublished per-rule counter must SKIP the sample —
// never a 0 standing in for an unknown (#3345) — but must NOT bump
// xpf_counter_read_errors_total. Routing a no-data window to the error counter
// is exactly the per-zone FALSE alert #3643 removed a whole metric family to
// stop; here it would fire once per counter-eligible rule per scrape for the
// entire warm-up window, and permanently under #5679 config skew. The omission
// is made visible by xpf_policy_counters_unpublished_rules instead, the policy
// sibling of xpf_zone_counters_unpopulated_zones.
//
// FAIL-ON-REVERT: restoring the bare `c.counterReadErrors.Add(1)` makes the
// counterReadErrors assertion RED; dropping the gauge emit makes the gauge
// assertion RED.
func TestCollectPolicyCountersUnpublishedDoesNotFalseAlert(t *testing.T) {
	srv := &Server{store: newUnpublishedPolicyAPIStore(t)}
	c := newCollector(srv)
	dp := &warmupPolicyAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)

	var hits int
	gauge := -1.0
	for m := range ch {
		switch descFQName(m.Desc().String()) {
		case "xpf_policy_hits_total":
			hits++
		case "xpf_policy_counters_unpublished_rules":
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("write gauge: %v", err)
			}
			gauge = pb.GetGauge().GetValue()
		}
	}

	if hits != 0 {
		t.Errorf("collectPolicyCounters emitted %d xpf_policy_hits_total samples for unpublished counters; want 0 (never a 0 standing in for an unknown, #3345)", hits)
	}
	if c.counterReadErrors.Load() != 0 {
		t.Errorf("counterReadErrors = %d, want 0: an unpublished counter is a no-data window, not a degraded read — bumping the error counter is the #3643 false alert (#7016)",
			c.counterReadErrors.Load())
	}
	// zone-pair rule + global rule + implicit default-policy row.
	if gauge != 3 {
		t.Errorf("xpf_policy_counters_unpublished_rules = %v, want 3 (zone-pair + global + default rows); the omission must be VISIBLE, not silent", gauge)
	}
}

// CONTROL: a genuine read failure must still bump counterReadErrors and must
// NOT be counted as unpublished. Without this, "do not bump" could be satisfied
// by never bumping at all.
func TestCollectPolicyCountersStillBumpsOnGenuineReadError(t *testing.T) {
	srv := &Server{store: newUnpublishedPolicyAPIStore(t)}
	c := newCollector(srv)
	dp := &bulkFailPolicyAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)

	gauge := -1.0
	for m := range ch {
		if descFQName(m.Desc().String()) == "xpf_policy_counters_unpublished_rules" {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("write gauge: %v", err)
			}
			gauge = pb.GetGauge().GetValue()
		}
	}

	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a genuine counter-bridge failure; the #3345/#3408 skip-and-bump contract must survive the #7016 relaxation")
	}
	if gauge != 0 {
		t.Errorf("xpf_policy_counters_unpublished_rules = %v on a genuine read FAILURE, want 0: a failure is not an unpublished counter", gauge)
	}
}
