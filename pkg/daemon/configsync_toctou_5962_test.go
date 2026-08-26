package daemon

// configsync_toctou_5962_test.go — the #5962 attempt-time/push-time TOCTOU.
//
// #5054 (PR #5958) routed every operator commit transport through
// commitAndApplyOperator, which resolved rg0ConfigSyncAuthority(d.cluster) into
// a bool BEFORE store.Commit and carried the answer to the push site. RG0
// ownership can move in between. The bool could not distinguish "this commit
// must never reach the peer" (the event-options engine's policy) from "this
// node is not the RG0 authority right now" (a fact with a lifetime), so the
// early answer was frozen and the push site's own re-check could only ever
// narrow it further.
//
// peerSyncPolicy carries the POLICY and resolves it once, at the push, after
// the commit succeeded. These tests pin BOTH directions, because the two fail
// opposite ways and a fix that only moved the evaluation later without keeping
// the never-policy distinct would pass one and fail the other:
//
//   - promotion in the window: the pre-fix code committed and SKIPPED the push,
//     leaving the new RG0 authority's own committed config unreplicated until
//     an unrelated reconnect reverse-sync.
//   - demotion in the window: the pre-fix code (had the attempt-time answer been
//     true) would push FROM a node that is no longer the authority, toward the
//     node that now is.

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// setRG0Ownership drives a live cluster.Manager across the RG0-authority
// boundary the same way the helpers in configsync_transport_5054_test.go build
// the two static states: RG0 present in the redundancy-group set (single-node
// election promotes the sole node) versus absent.
func setRG0Ownership(t *testing.T, m *cluster.Manager, own bool) {
	t.Helper()
	rgID := 0
	if !own {
		rgID = 1
	}
	m.UpdateConfig(&config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: rgID, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	if got := m.IsLocalPrimary(0); got != own {
		t.Fatalf("test setup: IsLocalPrimary(0) = %v, want %v", got, own)
	}
}

// TestOperatorCommitResolvesPeerSyncAtPushTime is the #5962 regression.
//
// The ownership flip is driven from the applyBodyForTest seam, which
// applyConfigLocked calls (daemon_apply.go:142) AFTER store.Commit has promoted
// the config and BEFORE applyAndSyncCommitted decides to push. That is exactly
// the window the issue describes, and it is the only place a test can stand in
// it without a sleep or a scheduler race.
func TestOperatorCommitResolvesPeerSyncAtPushTime(t *testing.T) {
	t.Run("promoted to RG0 authority inside the window: MUST push", func(t *testing.T) {
		cl := clusterNotOwningRG0(t)
		d, calls := newSyncProbeDaemon(t, cl)
		d.applyBodyForTest = func(_ *config.Config) { setRG0Ownership(t, cl, true) }

		if _, err := d.commitAndApplyOperator(t.Context(), configstore.InternalCommitter(), ""); err != nil {
			t.Fatalf("commitAndApplyOperator: %v", err)
		}
		if *calls != 1 {
			t.Fatalf("a node promoted to RG0 authority between the attempt-time gate "+
				"and the push committed successfully but pushed %d times, want 1 — "+
				"the peer keeps the PRIOR config until an unrelated reconnect "+
				"reverse-sync, and an RG failover in between silently restores "+
				"config the operator believed changed (#5962)", *calls)
		}
	})

	t.Run("demoted inside the window: MUST NOT push", func(t *testing.T) {
		cl := clusterOwningRG0(t)
		d, calls := newSyncProbeDaemon(t, cl)
		d.applyBodyForTest = func(_ *config.Config) { setRG0Ownership(t, cl, false) }

		if _, err := d.commitAndApplyOperator(t.Context(), configstore.InternalCommitter(), ""); err != nil {
			t.Fatalf("commitAndApplyOperator: %v", err)
		}
		if *calls != 0 {
			t.Fatalf("a node demoted out of RG0 authority during the commit pushed "+
				"%d times, want 0 — it would be overwriting the config of the node "+
				"that is now the authority (#5962)", *calls)
		}
	})

	// Controls: with ownership STABLE across the window the decision is
	// unchanged from #5054, in both states. Without these, a fix that simply
	// always pushed would pass the promotion case above.
	t.Run("stable owner: pushes once (control)", func(t *testing.T) {
		d, calls := newSyncProbeDaemon(t, clusterOwningRG0(t))
		if _, err := d.commitAndApplyOperator(t.Context(), configstore.InternalCommitter(), ""); err != nil {
			t.Fatalf("commitAndApplyOperator: %v", err)
		}
		if *calls != 1 {
			t.Fatalf("stable RG0 owner: pushes = %d, want 1", *calls)
		}
	})

	t.Run("stable non-owner: never pushes (control)", func(t *testing.T) {
		d, calls := newSyncProbeDaemon(t, clusterNotOwningRG0(t))
		if _, err := d.commitAndApplyOperator(t.Context(), configstore.InternalCommitter(), ""); err != nil {
			t.Fatalf("commitAndApplyOperator: %v", err)
		}
		if *calls != 0 {
			t.Fatalf("stable non-owner: pushes = %d, want 0", *calls)
		}
	})
}

// TestPeerSyncPolicyNeverIsNotAnAuthorityAnswer pins the distinction the bool
// could not express, and the reason this is a type rather than a moved call.
//
// peerSyncNever is the autonomous event-options engine's opt-out: each node
// fires its own remediation from its own RPM events and must never push that
// node-local state. It is FALSE on an RG0 owner, where an authority-gated
// policy is TRUE — so a fix that merely re-evaluated rg0ConfigSyncAuthority at
// the push site for every caller would have started replicating event-engine
// remediations to the peer.
func TestPeerSyncPolicyNeverIsNotAnAuthorityAnswer(t *testing.T) {
	owner := clusterOwningRG0(t)
	nonOwner := clusterNotOwningRG0(t)

	for _, tc := range []struct {
		name    string
		policy  peerSyncPolicy
		cl      *cluster.Manager
		want    bool
		because string
	}{
		{"never on an owner", peerSyncNever, owner, false,
			"the event-engine opt-out is a policy, not an authority answer"},
		{"never on a non-owner", peerSyncNever, nonOwner, false, ""},
		{"never with no cluster", peerSyncNever, nil, false, ""},
		{"authority-gated on an owner", peerSyncIfRG0Authority, owner, true, ""},
		{"authority-gated on a non-owner", peerSyncIfRG0Authority, nonOwner, false, ""},
		{"authority-gated with no cluster", peerSyncIfRG0Authority, nil, false,
			"a standalone node has no peer to push to"},
		{"always on a non-owner", peerSyncAlways, nonOwner, true,
			"peerSyncAlways deliberately bypasses the gate; production has no such caller"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.wantsPush(tc.cl); got != tc.want {
				t.Fatalf("wantsPush = %v, want %v — %s", got, tc.want, tc.because)
			}
		})
	}
}
