package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// multiAppExpansionConfig builds a config whose first policy matches an
// application-set "web-apps" expanding to two applications (junos-http,
// junos-https), followed by a single-application policy "allow-ssh", plus a
// global policy. This is the case the per-policy counter path got wrong before
// the regression was reverted: the helper aggregates the expanded rules under
// one stable RuleID per policy name, and the counter READ callers identify a
// policy by its SLICE index in zpp.Policies, not by the dataplane snapshot's
// span-accumulated PolicyID.
func multiAppExpansionConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {
			Name:         "web-apps",
			Applications: []string{"junos-http", "junos-https"},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{
			{
				Name:   "allow-web",
				Match:  config.PolicyMatch{Applications: []string{"web-apps"}},
				Action: config.PolicyPermit,
			},
			{
				Name:   "allow-ssh",
				Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
				Action: config.PolicyPermit,
			},
		},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:   "global-allow",
		Match:  config.PolicyMatch{Applications: []string{"web-apps"}},
		Action: config.PolicyPermit,
	}}
	return cfg
}

// callerCounterID mirrors EXACTLY how every production per-policy hit-count
// reader (pkg/api/metrics_counters.go policyCounterID, pkg/api/security.go,
// pkg/cli/cli_show_security*.go, pkg/grpcapi/server_show_*.go) builds the
// numeric handle it passes to ReadPolicyCounters: policySetID*MaxRulesPerPolicy
// plus the policy's raw SLICE index in zpp.Policies. The counter resolver must
// agree with this handle — NOT with the span-accumulated dataplane snapshot
// PolicyID.
func callerCounterID(policySetID uint32, sliceIndex int) uint32 {
	return policySetID*dataplane.MaxRulesPerPolicy + uint32(sliceIndex)
}

// Test_3143_CounterResolutionMatchesSliceIndexCallers verifies that the counter
// resolver decodes the SLICE-INDEX handle the production callers pass, so a
// policy that follows a multi-application policy resolves to its OWN stable rule
// ID. The bug guarded against is a span-accumulated resolver: it would map the
// caller's slice-index handle into the PRECEDING (expanded) policy's span and
// return the preceding policy's name. Restoring that span-accumulated resolver
// makes the allow-ssh assertion below resolve to allow-web → RED.
func Test_3143_CounterResolutionMatchesSliceIndexCallers(t *testing.T) {
	cfg := multiAppExpansionConfig()

	// allow-web is slice index 0, allow-ssh is slice index 1 in policy set 0.
	// The callers therefore read allow-ssh's counter with handle 1 — even
	// though allow-web expands to 2 dataplane rules.
	wantWeb := stablePolicyRuleID("lan", "wan", "allow-web")
	wantSSH := stablePolicyRuleID("lan", "wan", "allow-ssh")
	if got := policyRuleIDForCounter(cfg, callerCounterID(0, 0)); got != wantWeb {
		t.Fatalf("policyRuleIDForCounter(handle 0) = %q, want %q", got, wantWeb)
	}
	if got := policyRuleIDForCounter(cfg, callerCounterID(0, 1)); got != wantSSH {
		t.Fatalf("policyRuleIDForCounter(handle 1) = %q, want %q (allow-ssh, NOT the preceding allow-web)", got, wantSSH)
	}
	// Global policies are policy set index 1 (after the one zone-pair set);
	// global-allow is slice index 0 there.
	wantGlobal := stablePolicyRuleID("junos-global", "junos-global", "global-allow")
	if got := policyRuleIDForCounter(cfg, callerCounterID(1, 0)); got != wantGlobal {
		t.Fatalf("policyRuleIDForCounter(global handle) = %q, want %q", got, wantGlobal)
	}
}

// Test_3143_CounterE2EThroughCallerHandle is the end-to-end test the suite was
// missing: it combines application-set expansion with a counter assertion across
// the full caller → resolver → name-keyed helper store path. The helper reports
// each policy's hit count keyed by its stable RuleID (the expanded rules of
// allow-web aggregate under one "lan->wan/allow-web" counter); a caller reads
// allow-ssh with the slice-index handle and must get allow-ssh's count, not the
// preceding allow-web's.
//
// Fail-on-revert: with a span-accumulated resolver, ReadPolicyCounters(handle 1)
// resolves to allow-web and returns allow-web's 50/5000 instead of allow-ssh's
// 11/1100 → RED.
func Test_3143_CounterE2EThroughCallerHandle(t *testing.T) {
	cfg := multiAppExpansionConfig()
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-web"), Packets: 50, Bytes: 5000},
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-ssh"), Packets: 11, Bytes: 1100},
		},
	}

	// Iterate exactly as the production counter readers do.
	results := map[string]dataplane.CounterValue{}
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		for i, pol := range zpp.Policies {
			ctr, err := m.ReadPolicyCounters(callerCounterID(policySetID, i))
			if err != nil {
				t.Fatalf("ReadPolicyCounters(%s): %v", pol.Name, err)
			}
			results[pol.Name] = ctr
		}
		policySetID++
	}

	if got := results["allow-ssh"]; got != (dataplane.CounterValue{Packets: 11, Bytes: 1100}) {
		t.Fatalf("allow-ssh counter = %+v, want packets=11 bytes=1100 (NOT the preceding allow-web's 50/5000)", got)
	}
	if got := results["allow-web"]; got != (dataplane.CounterValue{Packets: 50, Bytes: 5000}) {
		t.Fatalf("allow-web counter = %+v, want packets=50 bytes=5000", got)
	}
}

// TestPolicyCounterResolverCountsNilPolicySetsLikeWalkPolicyRuleSlots pins the
// #3474 contract: a nil zone-pair slot in cfg.Security.Policies consumes a
// policy-set ID. walkPolicyRuleSlots and every production counter caller
// (pkg/api/security.go, pkg/api/metrics_counters.go) advance policySetID for a
// nil element, so the counter resolver MUST advance its set index in lockstep.
//
// Fixture: cfg.Security.Policies = [nil, {lan->wan, ...}]. The real zone-pair
// set therefore lives at policySetID == 1, which is exactly the handle the
// callers compute (callerCounterID(1, 0/1)).
//
// Fail-on-revert: with the resolver's nil branch skipping WITHOUT incrementing
// (the bug), it under-counts the set index by one, never matches currentSet==1,
// falls through to the global branch (empty GlobalPolicies here) and returns ""
// instead of the lan->wan rule IDs — so both assertions go RED.
func TestPolicyCounterResolverCountsNilPolicySetsLikeWalkPolicyRuleSlots(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		nil, // tolerant/HA-sync path can leave a nil zone-pair slot
		{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{
				{Name: "allow-web", Action: config.PolicyPermit},
				{Name: "allow-ssh", Action: config.PolicyPermit},
			},
		},
	}

	// The nil slot is policy set 0; the real zone-pair set is policy set 1. The
	// callers read its rules with handles callerCounterID(1, 0) and
	// callerCounterID(1, 1) — the resolver must agree.
	wantWeb := stablePolicyRuleID("lan", "wan", "allow-web")
	wantSSH := stablePolicyRuleID("lan", "wan", "allow-ssh")
	if got := policyRuleIDForCounter(cfg, callerCounterID(1, 0)); got != wantWeb {
		t.Fatalf("policyRuleIDForCounter(set 1, slice 0) = %q, want %q (a preceding nil slot must still consume a policy-set ID)", got, wantWeb)
	}
	if got := policyRuleIDForCounter(cfg, callerCounterID(1, 1)); got != wantSSH {
		t.Fatalf("policyRuleIDForCounter(set 1, slice 1) = %q, want %q", got, wantSSH)
	}

	// The resolver must agree with walkPolicyRuleSlots on which (set, slice)
	// every configured policy maps to. Cross-check that the set index the walker
	// assigns each non-nil policy resolves back to that policy's own rule ID.
	if err := walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		want := stablePolicyRuleID(slot.FromZone, slot.ToZone, slot.Policy.Name)
		if got := policyRuleIDForCounter(cfg, callerCounterID(slot.PolicySetID, int(slot.SliceIndex))); got != want {
			t.Fatalf("resolver/walker disagree at set %d slice %d: resolver=%q, walker=%q", slot.PolicySetID, slot.SliceIndex, got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("walkPolicyRuleSlots: %v", err)
	}

	// Control / no-regression: a config with NO leading nil still resolves both
	// rules at policy set 0 exactly as before.
	noNil := &config.Config{}
	noNil.Security.Policies = []*config.ZonePairPolicies{cfg.Security.Policies[1]}
	if got := policyRuleIDForCounter(noNil, callerCounterID(0, 0)); got != wantWeb {
		t.Fatalf("control (no nil): policyRuleIDForCounter(set 0, slice 0) = %q, want %q", got, wantWeb)
	}
	if got := policyRuleIDForCounter(noNil, callerCounterID(0, 1)); got != wantSSH {
		t.Fatalf("control (no nil): policyRuleIDForCounter(set 0, slice 1) = %q, want %q", got, wantSSH)
	}
}

// Test_3145_SnapshotPolicyIDIsSpanAccumulated documents the OTHER namespace: the
// dataplane snapshot's PolicyID is span-accumulated (advances by the app-set
// expansion count), distinct from the slice-index counter handle above. This is
// the namespace the MaxRulesPerPolicy cap (#3145) protects.
func Test_3145_SnapshotPolicyIDIsSpanAccumulated(t *testing.T) {
	cfg := multiAppExpansionConfig()
	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	ids := map[string]uint32{}
	for _, s := range snaps {
		ids[s.Name] = s.PolicyID
	}
	// allow-web expands to 2, so allow-ssh's snapshot PolicyID is 2 (span
	// accumulated), and the global set starts at MaxRulesPerPolicy.
	if ids["allow-web"] != 0 || ids["allow-ssh"] != 2 {
		t.Fatalf("snapshot PolicyID spacing: allow-web=%d allow-ssh=%d, want 0 and 2", ids["allow-web"], ids["allow-ssh"])
	}
	if ids["global-allow"] != dataplane.MaxRulesPerPolicy {
		t.Fatalf("global snapshot PolicyID = %d, want %d", ids["global-allow"], dataplane.MaxRulesPerPolicy)
	}
}

// bigAppSet registers an application-set "big-set" with nApps real member
// applications (so ExpandApplicationSet resolves each member) and returns the
// member list. Each member is a distinct tcp application.
func bigAppSet(cfg *config.Config, nApps int) {
	if cfg.Applications.Applications == nil {
		cfg.Applications.Applications = map[string]*config.Application{}
	}
	members := make([]string, 0, nApps)
	for i := 0; i < nApps; i++ {
		name := fmt.Sprintf("app-%d", i)
		cfg.Applications.Applications[name] = &config.Application{
			Name:            name,
			Protocol:        "tcp",
			DestinationPort: fmt.Sprintf("%d", 10000+i),
		}
		members = append(members, name)
	}
	if cfg.Applications.ApplicationSets == nil {
		cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{}
	}
	cfg.Applications.ApplicationSets["big-set"] = &config.ApplicationSet{Name: "big-set", Applications: members}
}

// singleBigPolicyConfig is one zone-pair set with a single policy whose app-set
// expands to nApps terms — so the set's cumulative expansion equals nApps.
func singleBigPolicyConfig(nApps int) *config.Config {
	cfg := &config.Config{}
	bigAppSet(cfg, nApps)
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name:   "big",
			Match:  config.PolicyMatch{Applications: []string{"big-set"}},
			Action: config.PolicyPermit,
		}},
	}}
	return cfg
}

// Test_3145_MaxRulesPerPolicyCap verifies the per-set MaxRulesPerPolicy cap on
// the LIVE userspace snapshot path. The 256-slot namespace is indices 0..255
// (the full MaxRulesPerPolicy range), so a set whose cumulative app-set
// expansion EXACTLY fills it (256 terms → IDs 0..255) builds; only an expansion
// that would require an ID at index >= 256 is rejected fail-closed.
//
// Fail-on-revert (#3404): with the off-by-one >= guard, the exact-256 case is
// rejected and this test's "256 builds" assertion fails RED.
func Test_3145_MaxRulesPerPolicyCap(t *testing.T) {
	const max = dataplane.MaxRulesPerPolicy

	// 255 effective terms: under the cap, build succeeds (IDs 0..254).
	if _, err := buildPolicySnapshots(singleBigPolicyConfig(max - 1)); err != nil {
		t.Fatalf("buildPolicySnapshots(255 apps) returned error, want success: %v", err)
	}
	// 256 effective terms: EXACTLY fills the namespace (IDs 0..255), accepted.
	// This is the #3404 boundary: rejected by the old >= guard, accepted by >.
	// buildPolicySnapshots emits one snapshot per POLICY (slot), so the single
	// big policy yields one snapshot whose span fills indices 0..255.
	snaps256, err := buildPolicySnapshots(singleBigPolicyConfig(max))
	if err != nil {
		t.Fatalf("buildPolicySnapshots(256 apps) returned error, want success (exact 256-fill is in-namespace): %v", err)
	}
	if len(snaps256) != 1 {
		t.Fatalf("buildPolicySnapshots(256-term single policy) emitted %d snapshots, want 1", len(snaps256))
	}
	// The exact-fill set must occupy IDs 0..255 — none at or past MaxRulesPerPolicy.
	for _, s := range snaps256 {
		if s.PolicyID >= max {
			t.Fatalf("256-fill snapshot %q has runtime ID %d >= %d (spilled out of its own namespace)", s.Name, s.PolicyID, max)
		}
	}
	// 257 effective terms: over the cap (would need index 256), rejected.
	if _, err := buildPolicySnapshots(singleBigPolicyConfig(max + 1)); err == nil {
		t.Fatalf("buildPolicySnapshots(257 apps) succeeded, want MaxRulesPerPolicy rejection")
	}
}

// Test_3404_ExactFillNoCrossSetCollision proves the corrected boundary keeps
// adjacent policy sets in disjoint ID namespaces. The first zone-pair set is
// filled with exactly MaxRulesPerPolicy (256) single-application policies
// (indices 0..255); a second set follows. The first set's last ID must be
// policySetID*256+255 and the second set's first ID must be (policySetID+1)*256,
// so the +1 boundary cannot let set N's last ID collide with set N+1's first.
//
// Fail-on-revert (#3404): the old >= guard rejects the exact 256-fill outright,
// so buildPolicySnapshots errors and this test fails RED at the build step.
func Test_3404_ExactFillNoCrossSetCollision(t *testing.T) {
	const max = dataplane.MaxRulesPerPolicy
	cfg := &config.Config{}
	first := make([]*config.Policy, 0, max)
	for i := 0; i < max; i++ {
		first = append(first, &config.Policy{
			Name:   fmt.Sprintf("rule-%d", i),
			Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
			Action: config.PolicyPermit,
		})
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "lan", ToZone: "wan", Policies: first},
		{FromZone: "dmz", ToZone: "wan", Policies: []*config.Policy{{
			Name:   "next-set-rule",
			Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
			Action: config.PolicyPermit,
		}}},
	}

	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots(exact 256-fill + second set): %v", err)
	}

	seen := map[uint32]string{}
	var firstMax, nextBase uint32
	haveNext := false
	for _, s := range snaps {
		key := stablePolicyRuleID(s.FromZone, s.ToZone, s.Name)
		if prev, ok := seen[s.PolicyID]; ok && prev != key {
			t.Fatalf("runtime policy ID %d shared by %q and %q (cross-set namespace collision)", s.PolicyID, prev, key)
		}
		seen[s.PolicyID] = key
		if s.FromZone == "lan" && s.PolicyID > firstMax {
			firstMax = s.PolicyID
		}
		if s.Name == "next-set-rule" {
			nextBase = s.PolicyID
			haveNext = true
		}
	}
	if firstMax != max-1 {
		t.Fatalf("first set's max runtime ID = %d, want %d (indices 0..255)", firstMax, max-1)
	}
	if !haveNext || nextBase != max {
		t.Fatalf("second set base runtime ID = %d, want %d (its own namespace, no overlap with first set's %d)", nextBase, max, firstMax)
	}
}

// Test_3145_NoSpillIntoNextPolicySet is the direct spill regression. The first
// zone-pair set has a policy expanding to exactly 256 terms followed by a
// one-app trailer; a second zone-pair set follows. WITHOUT the cap the trailer
// would be assigned runtime ID 256 — identical to the second set's base ID —
// colliding the two namespaces. WITH the cap the build is rejected fail-closed.
//
// Fail-on-revert: removing the cap makes buildPolicySnapshots succeed and emit
// two distinct policies sharing runtime ID 256, which this test detects.
func Test_3145_NoSpillIntoNextPolicySet(t *testing.T) {
	const max = dataplane.MaxRulesPerPolicy
	cfg := &config.Config{}
	bigAppSet(cfg, max) // first policy expands to 256 terms
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{
				{
					Name:   "big",
					Match:  config.PolicyMatch{Applications: []string{"big-set"}},
					Action: config.PolicyPermit,
				},
				{
					Name:   "trailer",
					Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
					Action: config.PolicyPermit,
				},
			},
		},
		{
			FromZone: "dmz",
			ToZone:   "wan",
			Policies: []*config.Policy{{
				Name:   "next-set-rule",
				Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
				Action: config.PolicyPermit,
			}},
		},
	}

	snaps, err := buildPolicySnapshots(cfg)
	if err == nil {
		// Cap was removed (revert): prove the spill actually occurred.
		seen := map[uint32]string{}
		for _, s := range snaps {
			key := stablePolicyRuleID(s.FromZone, s.ToZone, s.Name)
			if prev, ok := seen[s.PolicyID]; ok && prev != key {
				t.Fatalf("runtime policy ID %d shared by %q and %q (namespace spill into next policy set)", s.PolicyID, prev, key)
			}
			seen[s.PolicyID] = key
		}
		t.Fatal("buildPolicySnapshots accepted a 256-term expansion that spills into the next policy set; want MaxRulesPerPolicy rejection")
	}

	// A safe two-set config (first set under the cap) keeps the sets in
	// distinct namespaces with no shared runtime IDs.
	safe := &config.Config{}
	bigAppSet(safe, max-2) // 254 terms + 1-app trailer = 255 < 256
	safe.Security.Policies = cfg.Security.Policies
	snaps, err = buildPolicySnapshots(safe)
	if err != nil {
		t.Fatalf("buildPolicySnapshots(safe two-set): %v", err)
	}
	seen := map[uint32]string{}
	for _, s := range snaps {
		key := stablePolicyRuleID(s.FromZone, s.ToZone, s.Name)
		if prev, ok := seen[s.PolicyID]; ok && prev != key {
			t.Fatalf("runtime policy ID %d shared by %q and %q in safe config", s.PolicyID, prev, key)
		}
		seen[s.PolicyID] = key
	}
	for _, s := range snaps {
		if s.Name == "next-set-rule" && s.PolicyID < max {
			t.Fatalf("next-set-rule runtime ID = %d, want >= %d (its own policy-set namespace)", s.PolicyID, max)
		}
	}
}
