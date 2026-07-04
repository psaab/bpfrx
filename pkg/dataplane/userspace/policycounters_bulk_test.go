package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// buildManyPolicyConfig returns a config with `sets` zone-pair sets each holding
// `perSet` rules (perSet must stay below MaxRulesPerPolicy so the
// policySetID*MaxRulesPerPolicy+sliceIndex handle encoding is valid), the
// matching helper-published per-rule counters, and every valid policy handle.
// The k-th rule of set s gets packets = s*perSet+k+1, bytes = (s*perSet+k+1)*10.
func buildManyPolicyConfig(sets, perSet int) (*config.Config, []PolicyRuleCounterStatus, []uint32) {
	var zpps []*config.ZonePairPolicies
	var counters []PolicyRuleCounterStatus
	var ids []uint32
	for s := 0; s < sets; s++ {
		from := fmt.Sprintf("z%d", s)
		rules := make([]*config.Policy, perSet)
		for k := 0; k < perSet; k++ {
			name := fmt.Sprintf("rule-%d-%d", s, k)
			rules[k] = &config.Policy{Name: name}
			v := uint64(s*perSet + k + 1)
			counters = append(counters, PolicyRuleCounterStatus{
				RuleID:  stablePolicyRuleID(from, "wan", name),
				Packets: v,
				Bytes:   v * 10,
			})
			ids = append(ids, uint32(s)*dataplane.MaxRulesPerPolicy+uint32(k))
		}
		zpps = append(zpps, &config.ZonePairPolicies{FromZone: from, ToZone: "wan", Policies: rules})
	}
	cfg := &config.Config{Security: config.SecurityConfig{Policies: zpps}}
	return cfg, counters, ids
}

// TestReadAllPolicyCountersMatchesPerPolicy pins the bulk read's correctness: the
// per-policy value it returns is identical to the single ReadPolicyCounters for
// every handle (zone-pair rule, global rule, default-policy sentinel), and an
// unpublished policy is absent from the map (the same skip/error signal the
// per-policy read produced).
func TestReadAllPolicyCountersMatchesPerPolicy(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "lan",
				ToZone:   "wan",
				Policies: []*config.Policy{{Name: "allow-web"}, {Name: "allow-dns"}},
			}},
			GlobalPolicies: []*config.Policy{{Name: "global-allow"}},
		},
	}
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{PolicyRuleCounters: []PolicyRuleCounterStatus{
		{RuleID: stablePolicyRuleID("lan", "wan", "allow-dns"), Packets: 7, Bytes: 700},
		{RuleID: stablePolicyRuleID("junos-global", "junos-global", "global-allow"), Packets: 9, Bytes: 900},
		{RuleID: dataplane.DefaultPolicyName, Packets: 3, Bytes: 300},
	}}

	all, err := m.ReadAllPolicyCounters(cfg)
	if err != nil {
		t.Fatalf("ReadAllPolicyCounters: %v", err)
	}

	for _, id := range []uint32{1, dataplane.MaxRulesPerPolicy, dataplane.DefaultPolicySentinelID} {
		want, werr := m.ReadPolicyCounters(id)
		if werr != nil {
			t.Fatalf("ReadPolicyCounters(%d): %v", id, werr)
		}
		got, ok := all[id]
		if !ok {
			t.Fatalf("ReadAllPolicyCounters missing policy %d", id)
		}
		if got != want {
			t.Fatalf("policy %d: bulk=%+v single=%+v", id, got, want)
		}
	}

	// allow-web (slot 0) has no published counter: absent from the bulk map, and
	// the single read reports the unpublished signal (error).
	if v, ok := all[0]; ok {
		t.Fatalf("policy 0 (unpublished) unexpectedly present: %+v", v)
	}
	if _, err := m.ReadPolicyCounters(0); err == nil {
		t.Fatal("ReadPolicyCounters(0) returned nil error for an unpublished policy; expected the unpublished signal")
	}
}

// TestReadAllPolicyCountersBuildsIndexOnce is the O(P+C) RED-on-revert pin: the
// bulk read builds the ruleID->counter index EXACTLY ONCE for P policies, while
// the per-policy read (the pre-#3965 form the scrape used) rebuilds it on every
// call — O(P^2). Reverting ReadAllPolicyCounters to a per-policy index rebuild
// makes the want-1 assertion go RED.
func TestReadAllPolicyCountersBuildsIndexOnce(t *testing.T) {
	const sets, perSet = 16, 64
	const n = sets * perSet // 1024 policies
	cfg, counters, ids := buildManyPolicyConfig(sets, perSet)
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{PolicyRuleCounters: counters}

	var builds int
	policyRuleCounterIndexBuildObserver = func() { builds++ }
	defer func() { policyRuleCounterIndexBuildObserver = nil }()

	result, err := m.ReadAllPolicyCounters(cfg)
	if err != nil {
		t.Fatalf("ReadAllPolicyCounters: %v", err)
	}
	if builds != 1 {
		t.Fatalf("ReadAllPolicyCounters built the counter index %d times for %d policies; want 1 (O(P+C), not O(P^2))", builds, n)
	}
	if len(result) != n {
		t.Fatalf("ReadAllPolicyCounters returned %d counters; want %d", len(result), n)
	}
	// Spot-check: set 4, rule 10 -> value 4*64+10+1 = 267.
	if got := result[uint32(4)*dataplane.MaxRulesPerPolicy+10]; got != (dataplane.CounterValue{Packets: 267, Bytes: 2670}) {
		t.Fatalf("set4/rule10 counter = %+v, want {Packets:267 Bytes:2670}", got)
	}

	// Contrast: the pre-#3965 per-policy read rebuilt the index on EVERY call, so
	// the same P-policy read was O(P^2). Prove the scaling difference is real.
	builds = 0
	for _, id := range ids {
		if _, err := m.ReadPolicyCounters(id); err != nil {
			t.Fatalf("ReadPolicyCounters(%d): %v", id, err)
		}
	}
	if builds != n {
		t.Fatalf("per-policy read built the index %d times for %d policies; want %d (the O(P^2) form)", builds, n, n)
	}
}

// TestReadAllPolicyCountersReleasesLockBeforeResolution is the mutex-hold
// RED-on-revert pin: the bulk read holds the policy mutex only to copy the
// counter snapshot, then releases it and resolves the config OUTSIDE the lock.
// The resolve observer (which fires during the resolution phase) can therefore
// acquire m.mu. Reverting to hold m.mu across the whole read (e.g. a top-level
// `defer m.mu.Unlock()`) makes TryLock fail and the assertion go RED — the
// regression that starved commit/apply during a Prometheus scrape.
func TestReadAllPolicyCountersReleasesLockBeforeResolution(t *testing.T) {
	cfg, counters, _ := buildManyPolicyConfig(1, 64)
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{PolicyRuleCounters: counters}

	var fired, lockFree bool
	policyCounterResolveObserver = func() {
		fired = true
		if m.mu.TryLock() {
			m.mu.Unlock()
			lockFree = true
		}
	}
	defer func() { policyCounterResolveObserver = nil }()

	if _, err := m.ReadAllPolicyCounters(cfg); err != nil {
		t.Fatalf("ReadAllPolicyCounters: %v", err)
	}
	if !fired {
		t.Fatal("resolve observer never fired; ReadAllPolicyCounters did not reach the resolution phase")
	}
	if !lockFree {
		t.Fatal("policy mutex was held during resolution — snapshot-and-release regressed (read holds m.mu across the whole read, starving commit/apply)")
	}
}
