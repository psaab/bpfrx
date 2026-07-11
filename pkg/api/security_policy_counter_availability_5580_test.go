package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// unloadedPolicyAPIDP models a degraded / config-only boot: the dataplane
// object exists but is NOT loaded, so the policies handler never builds its
// per-policy counter reader (#5580). Embeds *dataplane.Manager to satisfy the
// apiRuntimeDataPlane interface and forces IsLoaded()=false.
type unloadedPolicyAPIDP struct {
	*dataplane.Manager
}

func (d *unloadedPolicyAPIDP) IsLoaded() bool { return false }

// fetchPolicies drives the REST security-policies inventory handler and
// returns the decoded rows.
func fetchPolicies(t *testing.T, s *Server) []PolicyInfo {
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
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	return resp.Data
}

func findRule(rows []PolicyInfo, name string) (PolicyRule, bool) {
	for _, pi := range rows {
		for _, r := range pi.Rules {
			if r.Name == name {
				return r, true
			}
		}
	}
	return PolicyRule{}, false
}

// TestPoliciesHandlerCounterAvailabilityUnloadedSystemWide is the #5580
// fail-on-revert guard. With system-wide `policy-stats` ENABLED and the
// dataplane UNLOADED, every counter-eligible rule (and the implicit
// default-policy row) MUST mark hit_counters_unavailable=true with 0/0 counts,
// NOT emit authoritative-looking zeroes. Reverting the security.go guard makes
// HitCountersUnavailable default to false while the handler still returns
// HTTP 200 with 0/0 — a monitor could not tell "no counter source" from "rule
// matched 0 packets" — so this test goes RED.
func TestPoliciesHandlerCounterAvailabilityUnloadedSystemWide(t *testing.T) {
	store := newSchedulerCounterAPIStore(t)
	enablePolicyStatsAPI(t, store)
	s := &Server{
		store: store,
		dp:    &unloadedPolicyAPIDP{Manager: dataplane.New()},
	}

	rows := fetchPolicies(t, s)

	// Both authored rules are counter-eligible when policy-stats is on.
	for _, name := range []string{"plain-allow", "scheduled-allow"} {
		rule, ok := findRule(rows, name)
		if !ok {
			t.Fatalf("%s rule missing from response", name)
		}
		if !rule.HitCountersUnavailable {
			t.Errorf("%s: HitCountersUnavailable = false, want true (dataplane unloaded, counter-eligible)", name)
		}
		if rule.HitPackets != 0 || rule.HitBytes != 0 {
			t.Errorf("%s: counters = %d/%d, want 0/0 when unavailable", name, rule.HitPackets, rule.HitBytes)
		}
	}

	// The implicit default-policy row is counter-eligible whenever policy-stats
	// is on; unloaded -> its 0/0 must be marked unavailable too.
	defRule, ok := findRule(rows, dataplane.DefaultPolicyName)
	if !ok {
		t.Fatalf("default-policy row missing from response")
	}
	if !defRule.HitCountersUnavailable {
		t.Errorf("default-policy: HitCountersUnavailable = false, want true (dataplane unloaded, policy-stats on)")
	}
}

// TestPoliciesHandlerCounterAvailabilityUnloadedThenCountOnly proves the
// "not counter-enabled" vs "counter-enabled but source unavailable"
// distinction (#5580). With policy-stats OFF and the dataplane UNLOADED:
//   - a rule WITHOUT `then count` (plain-allow) is legitimately no-counter:
//     Count=false and hit_counters_unavailable is OMITTED (false) — a real,
//     honest zero, not a degraded one.
//   - a rule WITH `then count` (scheduled-allow) is counter-eligible but has
//     no runtime source, so hit_counters_unavailable=true.
//   - the default-policy row is not eligible with the knob off -> not
//     unavailable.
func TestPoliciesHandlerCounterAvailabilityUnloadedThenCountOnly(t *testing.T) {
	store := newPolicyCounterAPIStoreNoStats(t)
	s := &Server{
		store: store,
		dp:    &unloadedPolicyAPIDP{Manager: dataplane.New()},
	}

	rows := fetchPolicies(t, s)

	plain, ok := findRule(rows, "plain-allow")
	if !ok {
		t.Fatal("plain-allow rule missing from response")
	}
	if plain.Count {
		t.Fatal("plain-allow Count = true, want false (no then count)")
	}
	if plain.HitCountersUnavailable {
		t.Error("plain-allow: HitCountersUnavailable = true, want false (not counter-enabled is not 'unavailable')")
	}

	scheduled, ok := findRule(rows, "scheduled-allow")
	if !ok {
		t.Fatal("scheduled-allow rule missing from response")
	}
	if !scheduled.Count {
		t.Fatal("scheduled-allow Count = false, want true (then count)")
	}
	if !scheduled.HitCountersUnavailable {
		t.Error("scheduled-allow: HitCountersUnavailable = false, want true (then count eligible, dataplane unloaded)")
	}
	if scheduled.HitPackets != 0 || scheduled.HitBytes != 0 {
		t.Errorf("scheduled-allow: counters = %d/%d, want 0/0 when unavailable", scheduled.HitPackets, scheduled.HitBytes)
	}

	defRule, ok := findRule(rows, dataplane.DefaultPolicyName)
	if !ok {
		t.Fatal("default-policy row missing from response")
	}
	if defRule.HitCountersUnavailable {
		t.Error("default-policy: HitCountersUnavailable = true, want false (policy-stats off -> not eligible)")
	}
}

// TestPoliciesHandlerCounterAvailabilityLoaded is the opposite pole: with the
// dataplane LOADED and policy-stats on, real counts serialize and availability
// is true (hit_counters_unavailable omitted/false) — the discriminator does not
// falsely flag a healthy read.
func TestPoliciesHandlerCounterAvailabilityLoaded(t *testing.T) {
	store := newSchedulerCounterAPIStore(t)
	enablePolicyStatsAPI(t, store)
	policyID := scheduledCounterPolicyID(t, store)
	s := &Server{
		store: store,
		dp: &schedulerCounterAPIDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				policyID: {Packets: 17, Bytes: 1700},
			},
		},
	}

	rows := fetchPolicies(t, s)

	scheduled, ok := findRule(rows, "scheduled-allow")
	if !ok {
		t.Fatal("scheduled-allow rule missing from response")
	}
	if scheduled.HitCountersUnavailable {
		t.Error("scheduled-allow: HitCountersUnavailable = true, want false (dataplane loaded, read ok)")
	}
	if scheduled.HitPackets != 17 || scheduled.HitBytes != 1700 {
		t.Errorf("scheduled-allow: counters = %d/%d, want 17/1700 (real counts)", scheduled.HitPackets, scheduled.HitBytes)
	}
}
