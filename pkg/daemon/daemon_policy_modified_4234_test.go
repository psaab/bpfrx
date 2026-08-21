package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #4234 modified-policy re-evaluation: when `security policies policy-rematch`
// is set, a surviving policy (same zones+name) whose MATCH or ACTION changed has
// its live sessions cleared at commit so the tightened policy re-evaluates
// traffic. Without policy-rematch, a modified policy's sessions keep forwarding
// (the historical behavior). These are the RED-on-revert tests for the core.

func withPolicyRematch(cfg *config.Config, extensive bool) *config.Config {
	cfg.Security.PolicyRematch = true
	cfg.Security.PolicyRematchExtensive = extensive
	return cfg
}

func TestChangedPolicyRuntimeIDs(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	webID := oldIDs["trust->untrust/p-web"]
	sshID := oldIDs["trust->untrust/p-ssh"]
	globID := oldIDs["junos-global->junos-global/glob-a"]

	t.Run("gate: no policy-rematch means empty even when a policy changed", func(t *testing.T) {
		newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny // p-web permit->deny
		if got := changedPolicyRuntimeIDs(old, newCfg, nil, nil); len(got) != 0 {
			t.Fatalf("without policy-rematch the changed set must be empty, got %v", got)
		}
	})

	t.Run("action change is reported by OLD id", func(t *testing.T) {
		newCfg := withPolicyRematch(
			twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), false)
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny // p-web permit->deny
		got := changedPolicyRuntimeIDs(old, newCfg, nil, nil)
		if _, ok := got[webID]; !ok {
			t.Errorf("changed set %v missing p-web old id %d after action change", got, webID)
		}
		if _, ok := got[sshID]; ok {
			t.Errorf("changed set %v wrongly contains unchanged p-ssh id %d", got, sshID)
		}
	})

	t.Run("match change is reported", func(t *testing.T) {
		newCfg := withPolicyRematch(
			twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), false)
		newCfg.Security.Policies[0].Policies[1].Match.SourceAddresses = []string{"10.0.0.0/8"}
		got := changedPolicyRuntimeIDs(old, newCfg, nil, nil)
		if _, ok := got[webID]; !ok {
			t.Errorf("changed set %v missing p-web after match change", got)
		}
	})

	t.Run("pure reorder of match addresses is NOT a change", func(t *testing.T) {
		old2 := twoPolicyConfig([]string{"p-a"}, nil)
		old2.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"a", "b", "c"}
		newCfg := withPolicyRematch(twoPolicyConfig([]string{"p-a"}, nil), false)
		newCfg.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"c", "a", "b"}
		if got := changedPolicyRuntimeIDs(old2, newCfg, nil, nil); len(got) != 0 {
			t.Fatalf("reordered address list wrongly reported as changed: %v", got)
		}
	})

	t.Run("deleted policy is NOT reported here (deletion-clear owns it)", func(t *testing.T) {
		newCfg := withPolicyRematch(
			twoPolicyConfig([]string{"p-first", "p-ssh"}, []string{"glob-a"}), false) // p-web deleted
		got := changedPolicyRuntimeIDs(old, newCfg, nil, nil)
		if _, ok := got[webID]; ok {
			t.Errorf("changed set %v wrongly contains DELETED p-web id %d", got, webID)
		}
	})

	t.Run("changed global policy is reported", func(t *testing.T) {
		newCfg := withPolicyRematch(
			twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), false)
		newCfg.Security.GlobalPolicies[0].Action = config.PolicyDeny
		got := changedPolicyRuntimeIDs(old, newCfg, nil, nil)
		if _, ok := got[globID]; !ok {
			t.Errorf("changed set %v missing changed global glob-a id %d", got, globID)
		}
	})

	t.Run("identical config changes nothing", func(t *testing.T) {
		newCfg := withPolicyRematch(
			twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), false)
		if got := changedPolicyRuntimeIDs(old, newCfg, nil, nil); len(got) != 0 {
			t.Fatalf("identical config produced changed set %v", got)
		}
	})

	t.Run("changing the FIRST policy never puts overloaded id 0 in the set", func(t *testing.T) {
		newCfg := withPolicyRematch(
			twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"}), false)
		newCfg.Security.Policies[0].Policies[0].Action = config.PolicyDeny // p-first (id 0) changed
		if _, ok := changedPolicyRuntimeIDs(old, newCfg, nil, nil)[0]; ok {
			t.Fatalf("changing the first policy wrongly put overloaded id 0 in the changed set")
		}
	})
}

// TestClearSessionsForModifiedPolicies is the RED-on-revert test for the core:
// with policy-rematch set, a session under a policy whose action changed is
// cleared; a session under an UNCHANGED policy is kept; and with policy-rematch
// UNSET the modified policy's session is kept (historical behavior).
func TestClearSessionsForModifiedPolicies(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	webID := oldIDs["trust->untrust/p-web"] // 1
	sshID := oldIDs["trust->untrust/p-ssh"] // 2

	webSess := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 40001, DstPort: 80, Protocol: 6}
	sshSess := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 40002, DstPort: 22, Protocol: 6}
	webSessV6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02}, SrcPort: 40003, DstPort: 80, Protocol: 6}

	newStore := func() *policyInvalTestDP {
		return &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{
				webSess: {State: dataplane.SessStateEstablished, PolicyID: webID},
				sshSess: {State: dataplane.SessStateEstablished, PolicyID: sshID},
			},
			v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
				webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
			},
		}
	}

	t.Run("policy-rematch set: changed policy sessions cleared, unchanged kept", func(t *testing.T) {
		newCfg := withPolicyRematch(twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil), false)
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny // p-web permit->deny
		dp := newStore()
		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForModifiedPolicies(old, newCfg)

		if _, ok := dp.v4[webSess]; ok {
			t.Errorf("v4 session under MODIFIED policy p-web survived policy-rematch clear")
		}
		if _, ok := dp.v6[webSessV6]; ok {
			t.Errorf("v6 session under MODIFIED policy p-web survived policy-rematch clear")
		}
		if _, ok := dp.v4[sshSess]; !ok {
			t.Errorf("session under UNCHANGED policy p-ssh was wrongly cleared")
		}
	})

	t.Run("policy-rematch UNSET: modified policy sessions kept", func(t *testing.T) {
		newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil) // no policy-rematch
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny
		dp := newStore()
		d := &Daemon{}
		d.setDataplane(dp) // #2114: publish through the cell
		d.clearSessionsForModifiedPolicies(old, newCfg)

		if _, ok := dp.v4[webSess]; !ok {
			t.Errorf("without policy-rematch, a modified policy's session must keep forwarding")
		}
		if dp.iterateCalls != 0 {
			t.Errorf("without policy-rematch the session table must not be scanned (%d iterate calls)", dp.iterateCalls)
		}
	})
}

// TestClearSessionsForPolicyIDs_EnumerateErrorNotSilent is the FIX 1 test
// (Copilot #4320): when the session-table enumeration fails, the shared clear
// core must NOT log an apparently-successful "cleared sessions" line — a
// partial clear has to be observable as an error, not masked. It still clears
// whatever it managed to gather (a partial clear beats none). RED on revert:
// with the ForEachV4/V6 error discarded, the success Info line fires and no
// error is surfaced.
func TestClearSessionsForPolicyIDs_EnumerateErrorNotSilent(t *testing.T) {
	sess := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 40001, DstPort: 80, Protocol: 6}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			sess: {State: dataplane.SessStateEstablished, PolicyID: 7},
		},
		iterErr: errors.New("dataplane iterator failed"),
	}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell
	d.clearSessionsForPolicyIDs(map[uint32]struct{}{7: {}}, dataplane.DeleteReasonPolicyModified, "modified (test)")

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("enumerate failed")) {
		t.Fatalf("expected an ERROR log about the failed enumerate, got:\n%s", out)
	}
	if bytes.Contains([]byte(out), []byte("cleared sessions of changed policies at commit")) {
		t.Fatalf("success line must be suppressed on enumerate error, got:\n%s", out)
	}
	// A partial clear still proceeds for what WAS enumerated.
	if _, ok := dp.v4[sess]; ok {
		t.Errorf("the gathered session should still be cleared (partial clear), but it survived")
	}
}
