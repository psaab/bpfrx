package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #4343 scheduler-binding invalidation: policyRuleInactive (userspace-dp) is
// FAIL-CLOSED — a policy bound to an inactive scheduler is skipped in the rule
// chain — so a scheduler active->inactive transition IS a verdict change for a
// live session, exactly like a permit->deny action tightening. Before #4343,
// policy-rematch ignored scheduler-name (listed among "non-verdict attributes"),
// so a policy that just went inactive kept forwarding its established sessions.
// These are the RED-on-revert tests: revert (scheduler-name ignored) detects no
// change and clears nothing.

// schedBoundPolicyConfig builds a trust->untrust config whose SECOND policy
// (p-web, non-zero id — p-first occupies the overloaded id 0) is bound to
// schedName, with policy-rematch optionally set and an optional scheduler def.
func schedBoundPolicyConfig(schedName string, sched *config.SchedulerConfig, rematch bool) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "p-first", Action: config.PolicyPermit},
			{Name: "p-web", Action: config.PolicyPermit, SchedulerName: schedName},
		}},
	}
	if sched != nil {
		cfg.Schedulers = map[string]*config.SchedulerConfig{sched.Name: sched}
	}
	cfg.Security.PolicyRematch = rematch
	return cfg
}

func TestChangedPolicyRuntimeIDs_SchedulerTransition(t *testing.T) {
	old := schedBoundPolicyConfig("biz", nil, false)
	webID := dpuserspace.PolicyIDsByStableKey(old)["trust->untrust/p-web"]
	if webID == 0 {
		t.Fatalf("precondition: p-web id must be non-zero (got 0 — overloaded wire value)")
	}

	t.Run("scheduler active->inactive is a verdict change (RED on revert)", func(t *testing.T) {
		newCfg := schedBoundPolicyConfig("biz", nil, true) // policy-rematch on; same match/action
		got := changedPolicyRuntimeIDs(old, newCfg, map[string]bool{"biz": true}, map[string]bool{"biz": false})
		if _, ok := got[webID]; !ok {
			t.Errorf("scheduler active->inactive did not mark p-web (id %d) as changed: %v", webID, got)
		}
	})

	t.Run("scheduler-name binding change to an inactive scheduler is a change", func(t *testing.T) {
		// old: unscheduled (always active). new: bound to inactive "night".
		oldUnsched := schedBoundPolicyConfig("", nil, false)
		newCfg := schedBoundPolicyConfig("night", nil, true)
		got := changedPolicyRuntimeIDs(oldUnsched, newCfg, nil, map[string]bool{"night": false})
		if _, ok := got[webID]; !ok {
			t.Errorf("binding an active policy to an inactive scheduler did not mark it changed: %v", got)
		}
	})

	t.Run("scheduler inactive->active is NOT a clear trigger", func(t *testing.T) {
		newCfg := schedBoundPolicyConfig("biz", nil, true)
		if got := changedPolicyRuntimeIDs(old, newCfg, map[string]bool{"biz": false}, map[string]bool{"biz": true}); len(got) != 0 {
			t.Errorf("inactive->active wrongly triggered a clear: %v", got)
		}
	})

	t.Run("still-active scheduler with no match/action change is not reported", func(t *testing.T) {
		newCfg := schedBoundPolicyConfig("biz", nil, true)
		if got := changedPolicyRuntimeIDs(old, newCfg, map[string]bool{"biz": true}, map[string]bool{"biz": true}); len(got) != 0 {
			t.Errorf("a still-active scheduler with no other change wrongly triggered a clear: %v", got)
		}
	})

	t.Run("scheduler flip WITHOUT policy-rematch changes nothing (gate holds)", func(t *testing.T) {
		newCfg := schedBoundPolicyConfig("biz", nil, false) // policy-rematch UNSET
		if got := changedPolicyRuntimeIDs(old, newCfg, map[string]bool{"biz": true}, map[string]bool{"biz": false}); len(got) != 0 {
			t.Errorf("without policy-rematch a scheduler flip must not clear: %v", got)
		}
	})
}

// TestClearSessionsForModifiedPolicies_SchedulerBecameInactive drives the full
// wiring: real scheduler defs (AllDay active -> past-date inactive) evaluated by
// clearSessionsForModifiedPolicies via policySchedulerActiveStateForApplyLocked
// (d.scheduler nil -> NewPrimed path), with policy-rematch set. The p-web session
// must be cleared purely because its scheduler went inactive (its match/action
// are unchanged). RED on revert: scheduler-name ignored -> session kept.
func TestClearSessionsForModifiedPolicies_SchedulerBecameInactive(t *testing.T) {
	activeSched := &config.SchedulerConfig{Name: "biz", Daily: true, AllDay: true}
	inactiveSched := &config.SchedulerConfig{Name: "biz", StartDate: "2000-01-01", StopDate: "2000-01-02"}

	old := schedBoundPolicyConfig("biz", activeSched, false)
	newCfg := schedBoundPolicyConfig("biz", inactiveSched, true) // policy-rematch on
	webID := dpuserspace.PolicyIDsByStableKey(old)["trust->untrust/p-web"]

	webSess := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 40001, DstPort: 80, Protocol: 6}
	webSessV6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02}, SrcPort: 40002, DstPort: 80, Protocol: 6}

	t.Run("active->inactive scheduler clears the policy's sessions", func(t *testing.T) {
		dp := &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{
				webSess: {State: dataplane.SessStateEstablished, PolicyID: webID},
			},
			v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
				webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
			},
		}
		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForModifiedPolicies(old, newCfg)

		if _, ok := dp.v4[webSess]; ok {
			t.Errorf("v4 session under a policy whose scheduler went inactive was not cleared")
		}
		if _, ok := dp.v6[webSessV6]; ok {
			t.Errorf("v6 session under a policy whose scheduler went inactive was not cleared")
		}
	})

	t.Run("no scheduler transition keeps the session (active->active)", func(t *testing.T) {
		steady := schedBoundPolicyConfig("biz", activeSched, true) // rematch on, still active
		dp := &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{
				webSess: {State: dataplane.SessStateEstablished, PolicyID: webID},
			},
		}
		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForModifiedPolicies(old, steady)

		if _, ok := dp.v4[webSess]; !ok {
			t.Errorf("a commit with no scheduler transition wrongly cleared the session")
		}
	})
}
