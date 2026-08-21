package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #4342 default-policy invalidation: a change to the IMPLICIT default-policy
// (permit-all -> deny/reject, or — under policy-rematch — a session-log flip)
// must clear the live default-PERMIT sessions, which carry the reserved
// DefaultPolicySentinelID (0xFFFFFFFF) rather than any configured policy_id. The
// named-policy invalidators never emit the sentinel, so before #4342 those flows
// forwarded with stale intent until idle timeout. These are the RED-on-revert
// tests: revert (no defaultPolicyChanged / no clearSessionsForDefaultPolicyChange
// wiring) leaves the default-permit sessions installed.

func TestDefaultPolicyChanged(t *testing.T) {
	base := func() *config.Config {
		c := &config.Config{}
		c.Security.DefaultPolicy = config.PolicyPermit
		return c
	}

	t.Run("nil configs report no change", func(t *testing.T) {
		if ch, _ := defaultPolicyChanged(nil, base()); ch {
			t.Errorf("nil old config reported a change")
		}
		if ch, _ := defaultPolicyChanged(base(), nil); ch {
			t.Errorf("nil new config reported a change")
		}
	})

	t.Run("action tightening permit->deny is unconditional", func(t *testing.T) {
		newCfg := base()
		newCfg.Security.DefaultPolicy = config.PolicyDeny
		ch, uncond := defaultPolicyChanged(base(), newCfg)
		if !ch || !uncond {
			t.Fatalf("permit->deny: changed=%v unconditional=%v, want true/true", ch, uncond)
		}
	})

	t.Run("action change permit->reject is unconditional", func(t *testing.T) {
		newCfg := base()
		newCfg.Security.DefaultPolicy = config.PolicyReject
		ch, uncond := defaultPolicyChanged(base(), newCfg)
		if !ch || !uncond {
			t.Fatalf("permit->reject: changed=%v unconditional=%v, want true/true", ch, uncond)
		}
	})

	t.Run("log-only flip is a gated (non-unconditional) change", func(t *testing.T) {
		newCfg := base()
		newCfg.Security.DefaultPolicyLogSessionInit = true
		ch, uncond := defaultPolicyChanged(base(), newCfg)
		if !ch || uncond {
			t.Fatalf("log-init flip: changed=%v unconditional=%v, want true/false", ch, uncond)
		}
		newCfg2 := base()
		newCfg2.Security.DefaultPolicyLogSessionClose = true
		ch, uncond = defaultPolicyChanged(base(), newCfg2)
		if !ch || uncond {
			t.Fatalf("log-close flip: changed=%v unconditional=%v, want true/false", ch, uncond)
		}
	})

	t.Run("identical default-policy reports no change", func(t *testing.T) {
		if ch, _ := defaultPolicyChanged(base(), base()); ch {
			t.Errorf("identical default-policy reported a change")
		}
	})
}

// defaultPolicyTestSessions returns a session store seeded with a default-PERMIT
// session (sentinel id), a configured-policy session (id 7), and an overloaded
// id-0 host-inbound/fabric/synced session. The sentinel sweep must clear ONLY
// the default-permit session and leave the other two untouched — in particular
// it must never alias the id-0 session (the H02 guard's concern).
func defaultPolicyTestSessions() (*policyInvalTestDP, dataplane.SessionKey, dataplane.SessionKey, dataplane.SessionKey, dataplane.SessionKeyV6) {
	defSess := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 40001, DstPort: 80, Protocol: 6}
	namedSess := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 40002, DstPort: 22, Protocol: 6}
	hostSess := dataplane.SessionKey{SrcIP: [4]byte{169, 254, 0, 1}, SrcPort: 0, DstPort: 179, Protocol: 6}
	defSessV6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02}, SrcPort: 40003, DstPort: 80, Protocol: 6}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			defSess:   {State: dataplane.SessStateEstablished, PolicyID: dataplane.DefaultPolicySentinelID},
			namedSess: {State: dataplane.SessStateEstablished, PolicyID: 7},
			hostSess:  {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			defSessV6: {State: dataplane.SessStateEstablished, PolicyID: dataplane.DefaultPolicySentinelID},
		},
	}
	return dp, defSess, namedSess, hostSess, defSessV6
}

func TestClearSessionsForDefaultPolicyChange(t *testing.T) {
	permit := func() *config.Config {
		c := &config.Config{}
		c.Security.DefaultPolicy = config.PolicyPermit
		return c
	}

	t.Run("permit->deny clears default-permit sessions, spares named + id-0", func(t *testing.T) {
		dp, defSess, namedSess, hostSess, defSessV6 := defaultPolicyTestSessions()
		newCfg := permit()
		newCfg.Security.DefaultPolicy = config.PolicyDeny

		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForDefaultPolicyChange(permit(), newCfg)

		if _, ok := dp.v4[defSess]; ok {
			t.Errorf("v4 default-permit (sentinel) session survived a permit->deny commit")
		}
		if _, ok := dp.v6[defSessV6]; ok {
			t.Errorf("v6 default-permit (sentinel) session survived a permit->deny commit")
		}
		if _, ok := dp.v4[namedSess]; !ok {
			t.Errorf("a configured-policy (id 7) session was wrongly cleared by the sentinel sweep")
		}
		if _, ok := dp.v4[hostSess]; !ok {
			t.Errorf("an id-0 host-local/fabric/synced session was wrongly swept by the sentinel sweep (sentinel must not alias id 0)")
		}
	})

	t.Run("log-only flip WITH policy-rematch clears default-permit sessions", func(t *testing.T) {
		dp, defSess, _, _, _ := defaultPolicyTestSessions()
		newCfg := permit()
		newCfg.Security.DefaultPolicyLogSessionInit = true
		newCfg.Security.PolicyRematch = true

		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForDefaultPolicyChange(permit(), newCfg)

		if _, ok := dp.v4[defSess]; ok {
			t.Errorf("default-permit session survived a log-flip commit with policy-rematch set")
		}
	})

	t.Run("log-only flip WITHOUT policy-rematch keeps default-permit sessions", func(t *testing.T) {
		dp, defSess, _, _, _ := defaultPolicyTestSessions()
		newCfg := permit()
		newCfg.Security.DefaultPolicyLogSessionClose = true // no policy-rematch

		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForDefaultPolicyChange(permit(), newCfg)

		if _, ok := dp.v4[defSess]; !ok {
			t.Errorf("a log-only flip without policy-rematch must not clear live default-permit sessions")
		}
		if dp.iterateCalls != 0 {
			t.Errorf("a gated log-flip without policy-rematch must not scan the session table (%d iterate calls)", dp.iterateCalls)
		}
	})

	t.Run("no default-policy change is a zero-cost no-op", func(t *testing.T) {
		dp, defSess, _, _, _ := defaultPolicyTestSessions()
		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForDefaultPolicyChange(permit(), permit())

		if _, ok := dp.v4[defSess]; !ok {
			t.Errorf("an unchanged default-policy cleared a default-permit session")
		}
		if dp.iterateCalls != 0 {
			t.Errorf("an unchanged default-policy scanned the session table (%d iterate calls); want a no-op", dp.iterateCalls)
		}
	})
}
