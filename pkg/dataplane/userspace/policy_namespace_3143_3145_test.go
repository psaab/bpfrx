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
// the LIVE userspace snapshot path. A set whose cumulative app-set expansion
// reaches 256 is rejected fail-closed; 255 builds. Reverting the cap in
// walkPolicyRuleSlots makes the 256/257 cases build, failing this test.
func Test_3145_MaxRulesPerPolicyCap(t *testing.T) {
	const max = dataplane.MaxRulesPerPolicy

	// 255 effective terms: under the cap, build succeeds (IDs 0..254).
	if _, err := buildPolicySnapshots(singleBigPolicyConfig(max - 1)); err != nil {
		t.Fatalf("buildPolicySnapshots(255 apps) returned error, want success: %v", err)
	}
	// 256 effective terms: at the cap, rejected.
	if _, err := buildPolicySnapshots(singleBigPolicyConfig(max)); err == nil {
		t.Fatalf("buildPolicySnapshots(256 apps) succeeded, want MaxRulesPerPolicy rejection")
	}
	// 257 effective terms: over the cap, rejected.
	if _, err := buildPolicySnapshots(singleBigPolicyConfig(max + 1)); err == nil {
		t.Fatalf("buildPolicySnapshots(257 apps) succeeded, want MaxRulesPerPolicy rejection")
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
