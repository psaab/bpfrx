package daemon

import (
	"context"
	"errors"
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
	// Three policies in one zone pair: p-first(id 0), p-web(id 1), p-ssh(id 2),
	// plus a global policy (id = 1*MaxRulesPerPolicy = 256, after the single
	// zone-pair set). p-first sits on the overloaded wire id 0.
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	firstID := oldIDs["trust->untrust/p-first"]
	webID := oldIDs["trust->untrust/p-web"]
	sshID := oldIDs["trust->untrust/p-ssh"]
	globID := oldIDs["junos-global->junos-global/glob-a"]
	if firstID != 0 {
		t.Fatalf("precondition: first policy id = %d, want 0", firstID)
	}
	if webID == 0 || globID == 0 {
		t.Fatalf("precondition: web=%d glob=%d must be non-zero", webID, globID)
	}

	t.Run("nil old config yields nothing", func(t *testing.T) {
		if got := deletedPolicyRuntimeIDs(nil, old); got != nil {
			t.Fatalf("deletedPolicyRuntimeIDs(nil, ...) = %v, want nil", got)
		}
	})

	t.Run("deleted zone-pair policy (id>=1) is reported by its OLD id", func(t *testing.T) {
		// Delete p-web (id 1); keep p-first and p-ssh (p-ssh shifts numeric id).
		newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[webID]; !ok {
			t.Errorf("deleted set %v missing p-web old id %d", got, webID)
		}
		if _, ok := got[sshID]; ok {
			t.Errorf("deleted set %v must NOT contain surviving p-ssh id %d", got, sshID)
		}
		if _, ok := got[globID]; ok {
			t.Errorf("deleted set %v must NOT contain surviving global id %d", got, globID)
		}
	})

	t.Run("deleting the FIRST policy never puts overloaded id 0 in the set", func(t *testing.T) {
		// p-first (id 0) deleted, p-web/p-ssh kept. policy_id 0 is the overloaded
		// wire value carried by host-local/fabric/tunnel/pre-#3056 sessions, so it
		// must be excluded from the clear set even though p-first was deleted.
		newCfg := twoPolicyConfig([]string{"p-web", "p-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[0]; ok {
			t.Fatalf("policy_id 0 must never enter the deleted set (overloaded wire value); got %v", got)
		}
	})

	t.Run("renaming the first policy never puts id 0 in the set", func(t *testing.T) {
		// A rename is delete(old-name)+add(new-name) by stable key; the deleted
		// old-name sits at id 0, which must still be excluded.
		newCfg := twoPolicyConfig([]string{"p-first-v2", "p-web", "p-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[0]; ok {
			t.Fatalf("renaming the first policy wrongly put id 0 in the deleted set: %v", got)
		}
	})

	t.Run("modified policy (same zones+name) is NOT reported", func(t *testing.T) {
		// p-web keeps its name+zones but flips permit->deny. Its stable key is
		// unchanged, so it is a MODIFIED policy, not a deleted one — the deferred
		// #4234 policy-rematch half, out of scope for the deletion-clear.
		newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny
		if got := deletedPolicyRuntimeIDs(old, newCfg); len(got) != 0 {
			t.Fatalf("a modified (not deleted) policy triggered a clear set %v, want empty", got)
		}
	})

	t.Run("deleted global policy is reported", func(t *testing.T) {
		newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
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
// admitted under a policy that the commit DELETES (id >= 1) is invalidated,
// while a session under a surviving (or merely modified) policy keeps
// forwarding — and a session on the overloaded id 0 is never swept even though
// the first policy was deleted.
func TestClearSessionsForDeletedPolicies(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	webID := oldIDs["trust->untrust/p-web"] // 1
	sshID := oldIDs["trust->untrust/p-ssh"] // 2

	// Delete p-first (id 0) AND p-web (id 1); keep p-ssh, modified permit->deny.
	// The clear is ACTIVE (deleted set = {1}) so this also proves the id-0 guard
	// holds while the sweep runs.
	newCfg := twoPolicyConfig([]string{"p-ssh"}, nil)
	newCfg.Security.Policies[0].Policies[0].Action = config.PolicyDeny

	webSess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	sshSess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40002, DstPort: 22, Protocol: 6,
	}
	// Stand-in for a host-inbound / fabric / tunnel / pre-#3056 synced session:
	// carries the overloaded policy_id 0.
	hostLocalSess := dataplane.SessionKey{
		SrcIP: [4]byte{169, 254, 0, 1}, DstIP: [4]byte{169, 254, 0, 2},
		SrcPort: 0, DstPort: 179, Protocol: 6,
	}
	webSessV6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}

	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess:       {State: dataplane.SessStateEstablished, PolicyID: webID},
			sshSess:       {State: dataplane.SessStateEstablished, PolicyID: sshID},
			hostLocalSess: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}

	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[webSess]; ok {
		t.Errorf("session under DELETED policy p-web (id %d) survived the commit clear", webID)
	}
	if _, ok := dp.v6[webSessV6]; ok {
		t.Errorf("v6 session under DELETED policy p-web (id %d) survived the commit clear", webID)
	}
	if _, ok := dp.v4[sshSess]; !ok {
		t.Errorf("session under SURVIVING (modified) policy p-ssh (id %d) was wrongly cleared", sshID)
	}
	if _, ok := dp.v4[hostLocalSess]; !ok {
		t.Errorf("id-0 host-local session was swept when the first policy was deleted (overloaded wire value must be excluded)")
	}
}

// TestClearSessionsForDeletedPolicies_FirstPolicyIdZeroNotSwept pins the id-0
// guard directly: deleting the FIRST policy (policy_id 0) must NOT clear the
// host-local / fabric / peer-synced sessions that also carry policy_id 0. RED on
// revert: without the id-0 exclusion in deletedPolicyRuntimeIDs, deleting the
// first policy puts 0 in the set and mass-clears every id-0 session (a
// rolling-upgrade / host-local forwarding outage, amplified by delete-sync).
func TestClearSessionsForDeletedPolicies_FirstPolicyIdZeroNotSwept(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web"}, nil)
	// Delete the first policy (id 0). p-web survives.
	newCfg := twoPolicyConfig([]string{"p-web"}, nil)

	hostSess := dataplane.SessionKey{SrcIP: [4]byte{169, 254, 0, 1}, SrcPort: 0, DstPort: 179, Protocol: 6}
	fabricSess := dataplane.SessionKey{SrcIP: [4]byte{10, 99, 0, 1}, SrcPort: 5000, DstPort: 5001, Protocol: 17}
	syncedV6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0xfe, 0x80, 15: 0x01}, SrcPort: 100, DstPort: 200, Protocol: 6}

	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			hostSess:   {State: dataplane.SessStateEstablished, PolicyID: 0},
			fabricSess: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			syncedV6: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[hostSess]; !ok {
		t.Errorf("host-inbound id-0 session cleared on first-policy delete")
	}
	if _, ok := dp.v4[fabricSess]; !ok {
		t.Errorf("fabric id-0 session cleared on first-policy delete")
	}
	if _, ok := dp.v6[syncedV6]; !ok {
		t.Errorf("v6 synced id-0 session cleared on first-policy delete")
	}
}

// TestClearSessionsForDeletedPolicies_RenameFirstPolicyNotSwept pins that
// renaming the first policy (delete old-name + add new-name at id 0) does not
// wipe id-0 sessions. RED on revert: without the guard, the rename puts 0 in the
// set, the sweep runs, and the id-0 session is cleared.
func TestClearSessionsForDeletedPolicies_RenameFirstPolicyNotSwept(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first-v2", "p-web"}, nil)

	hostSess := dataplane.SessionKey{SrcIP: [4]byte{169, 254, 0, 1}, SrcPort: 0, DstPort: 179, Protocol: 6}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			hostSess: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[hostSess]; !ok {
		t.Errorf("id-0 host-local session wiped when the first policy was RENAMED")
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
	d := &Daemon{}
	d.setDataplane(dp)
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
	// iterErr, when non-nil, is returned by BatchIterateSessions AFTER yielding
	// its entries — models a dataplane iterator that fails partway, exercising
	// the enumerate-error path in clearSessionsForPolicyIDs (Copilot #4320).
	iterErr error
	// delErr, when non-nil, is returned by BatchDeleteSessions/V6 WITHOUT
	// deleting anything — models a dataplane batch-delete that fails, so the
	// MATCHED sessions stay INSTALLED. Exercises the delete-error propagation
	// path in clearSessionsForPolicyIDs (#5578 stale-authorization gap).
	delErr error
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
	return d.iterErr
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
	if d.delErr != nil {
		// Model a failed batch delete: nothing is removed, so the matched
		// sessions stay installed under their now-stale authorization.
		return 0, d.delErr
	}
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
	if d.delErr != nil {
		return 0, d.delErr
	}
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

// deletedPolicyInvalFixture builds an old/new config pair that DELETES p-web
// (id 1) plus a fake DP whose v4 + v6 session tables each hold one session
// admitted by that deleted policy — the setup the #5578 error-propagation
// tests reuse. p-first (id 0) and p-ssh (id 2) survive so the clear set is the
// single non-overloaded deleted id {1}.
func deletedPolicyInvalFixture() (oldCfg, newCfg *config.Config, dp *policyInvalTestDP, webSess dataplane.SessionKey, webSessV6 dataplane.SessionKeyV6) {
	oldCfg = twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg = twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	webID := dpuserspace.PolicyIDsByStableKey(oldCfg)["trust->untrust/p-web"]

	webSess = dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	webSessV6 = dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}
	dp = &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}
	return oldCfg, newCfg, dp, webSess, webSessV6
}

// TestClearSessionsForPolicyIDsEnumerateErrorPropagates is the #5578
// RED-on-revert for a failed session-table ENUMERATE: a partial ForEachV4/V6
// iteration leaves unvisited sessions of the deleted policy in the live table.
// The helper must RETURN that error (wrapping the injected iterator error), not
// reduce it to a slog line. RED on revert: with the void/slog-only helper there
// is no return value to assert, so the compile fails / the error is lost.
func TestClearSessionsForPolicyIDsEnumerateErrorPropagates(t *testing.T) {
	oldCfg, newCfg, dp, _, _ := deletedPolicyInvalFixture()
	errBoom := errors.New("v4 iterator exploded")
	dp.iterErr = errBoom

	d := &Daemon{}
	d.setDataplane(dp)

	err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg)
	if err == nil {
		t.Fatal("clearSessionsForDeletedPolicies swallowed a session-table enumerate error; " +
			"a partial invalidation must be RETURNED so the commit can surface the stale-authorization gap (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("returned error %v does not wrap the injected iterator error", err)
	}

	// The combined helper the commit/sync/rollback callers use must also
	// propagate it (errors.Join threads every wrapper's error through).
	if joined := d.clearSessionsForPolicyChanges(oldCfg, newCfg); !errors.Is(joined, errBoom) {
		t.Fatalf("clearSessionsForPolicyChanges dropped the enumerate error: %v", joined)
	}
}

// TestClearSessionsForPolicyIDsDeleteErrorPropagates is the #5578 RED-on-revert
// for a failed batch DELETE: the matched sessions of the deleted policy stay
// INSTALLED (stale authorization) yet the pre-fix helper reduced the failure to
// a slog.Warn. The helper must RETURN the error AND the sessions must remain in
// the table — proving the security gap (traffic the new policy should deny keeps
// forwarding) is now observable to the caller, not silently swallowed.
func TestClearSessionsForPolicyIDsDeleteErrorPropagates(t *testing.T) {
	oldCfg, newCfg, dp, webSess, webSessV6 := deletedPolicyInvalFixture()
	errBoom := errors.New("batch delete failed")
	dp.delErr = errBoom

	d := &Daemon{}
	d.setDataplane(dp)

	err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg)
	if err == nil {
		t.Fatal("clearSessionsForDeletedPolicies swallowed a batch-delete failure; the matched " +
			"sessions stay installed under stale authorization and the commit must see the error (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("returned error %v does not wrap the injected delete error", err)
	}
	// The stale-authorization gap: the delete failed, so the sessions the new
	// policy should have revoked are still forwarding.
	if _, ok := dp.v4[webSess]; !ok {
		t.Error("precondition: v4 session should still be present after a failed delete (models stale authorization)")
	}
	if _, ok := dp.v6[webSessV6]; !ok {
		t.Error("precondition: v6 session should still be present after a failed delete (models stale authorization)")
	}
}

// TestApplyAndSyncCommittedSurfacesInvalidationError proves the CALLER surfaces
// the propagated error (#5578): a successful config apply whose post-apply
// policy-session invalidation fails must return a non-nil commit error while
// still committing the config (mark-and-continue, mirroring the non-fatal
// applyErr path). RED on revert: dropping the errors.Join(applyErr, clearErr) in
// applyAndSyncCommitted (or reverting the helper to void) makes this return nil.
func TestApplyAndSyncCommittedSurfacesInvalidationError(t *testing.T) {
	oldActive, compiled, dp, _, _ := deletedPolicyInvalFixture()
	errBoom := errors.New("batch delete failed")
	dp.delErr = errBoom

	d := &Daemon{
		// Bypass the heavy reconcile: the apply "succeeds" so the post-apply
		// invalidation runs and its error is the only thing under test.
		applyBodyForTest: func(*config.Config) {},
		applyErrForTest:  nil,
	}
	d.setDataplane(dp) // #2114: publish through the cell

	// peerSyncNever: no cluster wiring needed; the peer push is orthogonal.
	got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
	if err == nil {
		t.Fatal("applyAndSyncCommitted returned nil error despite a failed policy session " +
			"invalidation; the stale-authorization gap was swallowed (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("commit error %v does not carry the invalidation failure", err)
	}
	// Mark-and-continue: the config is still committed + active (returned),
	// mirroring how a non-fatal applyErr is surfaced alongside compiled.
	if got != compiled {
		t.Fatalf("applyAndSyncCommitted returned config %p, want the committed config %p "+
			"(a non-fatal invalidation error must not drop the commit)", got, compiled)
	}
}
