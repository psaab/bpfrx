package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// twoPolicyConfig builds a config with a single trust->untrust zone pair
// carrying the named permit policies plus the named global permit policies.
func twoPolicyConfig(zonePair []string, global []string) *config.Config {
	cfg := &config.Config{}
	if len(zonePair) > 0 {
		pols := make([]*config.Policy, 0, len(zonePair))
		for _, name := range zonePair {
			pols = append(pols, &config.Policy{Name: name, Action: config.PolicyPermit})
		}
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{FromZone: "trust", ToZone: "untrust", Policies: pols},
		}
	}
	for _, name := range global {
		cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies,
			&config.Policy{Name: name, Action: config.PolicyPermit})
	}
	return cfg
}

func TestDeletedPolicyRuntimeIDs(t *testing.T) {
	old := twoPolicyConfig([]string{"allow-web", "allow-ssh"}, []string{"glob-a"})
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	webID := oldIDs["trust->untrust/allow-web"]
	sshID := oldIDs["trust->untrust/allow-ssh"]
	globID := oldIDs["junos-global->junos-global/glob-a"]

	t.Run("nil old config yields nothing", func(t *testing.T) {
		if got := deletedPolicyRuntimeIDs(nil, old); got != nil {
			t.Fatalf("deletedPolicyRuntimeIDs(nil, ...) = %v, want nil", got)
		}
	})

	t.Run("deleted zone-pair policy is reported by its OLD id", func(t *testing.T) {
		// Delete allow-web; keep allow-ssh (which shifts to a new numeric id).
		newCfg := twoPolicyConfig([]string{"allow-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[webID]; !ok {
			t.Errorf("deleted set %v missing allow-web old id %d", got, webID)
		}
		if _, ok := got[sshID]; ok {
			t.Errorf("deleted set %v must NOT contain surviving allow-ssh id %d", got, sshID)
		}
		if _, ok := got[globID]; ok {
			t.Errorf("deleted set %v must NOT contain surviving global id %d", got, globID)
		}
	})

	t.Run("modified policy (same zones+name) is NOT reported", func(t *testing.T) {
		// allow-ssh keeps its name+zones but flips permit->deny. Its stable key
		// is unchanged, so it is a MODIFIED policy, not a deleted one — the
		// deferred #4234 policy-rematch half, out of scope for the deletion-clear.
		newCfg := twoPolicyConfig([]string{"allow-web", "allow-ssh"}, []string{"glob-a"})
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny
		if got := deletedPolicyRuntimeIDs(old, newCfg); len(got) != 0 {
			t.Fatalf("a modified (not deleted) policy triggered a clear set %v, want empty", got)
		}
	})

	t.Run("deleted global policy is reported", func(t *testing.T) {
		newCfg := twoPolicyConfig([]string{"allow-web", "allow-ssh"}, nil)
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[globID]; !ok {
			t.Errorf("deleted set %v missing global glob-a id %d", got, globID)
		}
	})

	t.Run("identical config deletes nothing", func(t *testing.T) {
		if got := deletedPolicyRuntimeIDs(old, old); len(got) != 0 {
			t.Fatalf("identical old/new produced clear set %v, want empty", got)
		}
	})
}

// TestClearSessionsForDeletedPolicies is the RED-on-revert test: a session
// admitted under a policy that the commit DELETES is invalidated, while a
// session under a surviving (or merely modified) policy keeps forwarding.
func TestClearSessionsForDeletedPolicies(t *testing.T) {
	old := twoPolicyConfig([]string{"allow-web", "allow-ssh"}, nil)
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	webID := oldIDs["trust->untrust/allow-web"]
	sshID := oldIDs["trust->untrust/allow-ssh"]

	// allow-web deleted; allow-ssh kept but modified (permit->deny) — the
	// modified one must NOT be cleared.
	newCfg := twoPolicyConfig([]string{"allow-ssh"}, nil)

	webSess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	sshSess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40002, DstPort: 22, Protocol: 6,
	}
	webSessV6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}

	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webID},
			sshSess: {State: dataplane.SessStateEstablished, PolicyID: sshID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}

	d := &Daemon{dp: dp}
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[webSess]; ok {
		t.Errorf("session under DELETED policy allow-web (id %d) survived the commit clear", webID)
	}
	if _, ok := dp.v6[webSessV6]; ok {
		t.Errorf("v6 session under DELETED policy allow-web (id %d) survived the commit clear", webID)
	}
	if _, ok := dp.v4[sshSess]; !ok {
		t.Errorf("session under SURVIVING (modified) policy allow-ssh (id %d) was wrongly cleared", sshID)
	}
}

func TestClearSessionsForDeletedPolicies_NoDeletionIsNoop(t *testing.T) {
	old := twoPolicyConfig([]string{"allow-web"}, nil)
	newCfg := twoPolicyConfig([]string{"allow-web"}, nil)
	webID := dpuserspace.PolicyIDsByStableKey(old)["trust->untrust/allow-web"]

	sess := dataplane.SessionKey{SrcPort: 1, Protocol: 6}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			sess: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}
	d := &Daemon{dp: dp}
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[sess]; !ok {
		t.Fatalf("a commit with no policy deletion cleared a session")
	}
	if dp.iterateCalls != 0 {
		t.Fatalf("no-deletion commit scanned the session table (%d iterate calls); want a zero-cost no-op", dp.iterateCalls)
	}
}

// policyInvalTestDP is an in-memory RuntimeDataPlane whose session store backs
// onto plain maps, enough to exercise the commit-time deletion-clear.
type policyInvalTestDP struct {
	dataplane.DataPlane // embedded nil — only the overridden methods are called

	v4           map[dataplane.SessionKey]dataplane.SessionValue
	v6           map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	iterateCalls int
}

func (d *policyInvalTestDP) Start(context.Context) error { return nil }
func (d *policyInvalTestDP) Close() error                { return nil }
func (d *policyInvalTestDP) Teardown() error             { return nil }

func (d *policyInvalTestDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return &dataplane.ApplyResult{}, nil
}
func (d *policyInvalTestDP) LastApplyResult() *dataplane.ApplyResult { return &dataplane.ApplyResult{} }
func (d *policyInvalTestDP) Link() dataplane.LinkController          { return noopLinkController{} }
func (d *policyInvalTestDP) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}
func (d *policyInvalTestDP) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(d)
}
func (d *policyInvalTestDP) Telemetry() dataplane.Telemetry                  { return dataplane.TelemetryOf(nil) }
func (d *policyInvalTestDP) SessionDeltas() dpruntime.SessionDeltaSource     { return nil }
func (d *policyInvalTestDP) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }

func (d *policyInvalTestDP) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.iterateCalls++
	for k, v := range d.v4 {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *policyInvalTestDP) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range d.v6 {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *policyInvalTestDP) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	n := 0
	for _, k := range keys {
		if _, ok := d.v4[k]; ok {
			delete(d.v4, k)
			n++
		}
	}
	return n, nil
}

func (d *policyInvalTestDP) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	n := 0
	for _, k := range keys {
		if _, ok := d.v6[k]; ok {
			delete(d.v6, k)
			n++
		}
	}
	return n, nil
}

func (d *policyInvalTestDP) DeleteDNATEntry(dataplane.DNATKey) error     { return nil }
func (d *policyInvalTestDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error { return nil }
