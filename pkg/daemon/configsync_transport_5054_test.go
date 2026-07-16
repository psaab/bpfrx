// #5054: REST and local-shell commits skipped peer config-sync while gRPC did
// not, so after a REST/shell commit a healthy HA cluster stayed diverged until
// an unrelated transport-disconnect reverse-sync — an RG failover could then
// silently restore config the operator believed changed.
//
// The fix makes the peer-sync decision transport-independent: all operator
// commit paths (gRPC / REST / local shell) route through commitAndApplyOperator
// / commitConfirmedAndApplyOperator, which derive the decision from RG0
// ownership (rg0ConfigSyncAuthority) rather than a per-transport constant. The
// autonomous event-options engine keeps its explicit opt-out (syncPeer=false)
// because each node fires remediation independently from its own RPM events.
//
// These tests pin (1) the pure decision function across the cluster-state table
// and (2) the behavioral outcome: an operator commit syncs the peer iff this
// node owns RG0, a standalone / non-owner node does not, and the event-engine
// opt-out still suppresses the sync even on an RG0 owner.
//
// FAIL-ON-REVERT: reverting commitAndApplyOperator (or the REST/shell wiring) to
// pass syncPeer=false turns TestOperatorCommitSyncsPeerWhenRG0Owner /
// TestOperatorCommitConfirmedSyncsPeerWhenRG0Owner RED (0 pushes → standby stays
// stale). Neutralizing rg0ConfigSyncAuthority to always-false turns both the
// owner decision-table case and those behavioral tests RED.
package daemon

import (
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// clusterOwningRG0 builds a cluster.Manager whose local node (0) owns RG0. A
// freshly constructed manager has no live peer, so UpdateConfig's single-node
// election promotes the sole node to RG0 primary.
func clusterOwningRG0(t *testing.T) *cluster.Manager {
	t.Helper()
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	if !m.IsLocalPrimary(0) {
		t.Fatal("test setup: expected local node to own RG0")
	}
	return m
}

// clusterNotOwningRG0 builds a configured cluster.Manager where the local node
// is NOT the RG0 config authority (RG0 is absent → IsLocalPrimary(0) is false),
// modeling a node whose peer owns the config-ownership group.
func clusterNotOwningRG0(t *testing.T) *cluster.Manager {
	t.Helper()
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	if m.IsLocalPrimary(0) {
		t.Fatal("test setup: local node must not own RG0")
	}
	return m
}

// TestRG0ConfigSyncAuthorityDecision is the load-bearing pure-decision table:
// the peer-sync policy depends ONLY on cluster/RG0 state, never on transport, so
// gRPC/REST/shell all resolve identically for a given cluster state.
func TestRG0ConfigSyncAuthorityDecision(t *testing.T) {
	cases := []struct {
		name string
		cl   *cluster.Manager
		want bool
	}{
		{"standalone-nil-cluster", nil, false},
		{"cluster-rg0-owner", clusterOwningRG0(t), true},
		{"cluster-non-owner", clusterNotOwningRG0(t), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rg0ConfigSyncAuthority(tc.cl); got != tc.want {
				t.Fatalf("rg0ConfigSyncAuthority(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// newSyncProbeDaemon builds a bare daemon with a committed baseline and a staged
// change (so a commit has a real diff), a stubbed apply body, and a
// syncPeerForTest recorder. The returned pointer counts peer-push attempts.
func newSyncProbeDaemon(t *testing.T, cl *cluster.Manager) (*Daemon, *int) {
	t.Helper()
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s, cluster: cl}
	d.applyBodyForTest = func(_ *config.Config) {}
	calls := 0
	d.syncPeerForTest = func() { calls++ }
	return d, &calls
}

// TestOperatorCommitSyncsPeerWhenRG0Owner: an operator commit on the RG0 owner
// pushes the committed config to the peer exactly once — regardless of which
// transport delivered it, since all route through commitAndApplyOperator.
func TestOperatorCommitSyncsPeerWhenRG0Owner(t *testing.T) {
	d, calls := newSyncProbeDaemon(t, clusterOwningRG0(t))

	if _, err := d.commitAndApplyOperator(t.Context(), ""); err != nil {
		t.Fatalf("commitAndApplyOperator: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("operator commit on the RG0 owner must sync the peer exactly once (#5054); got %d", *calls)
	}
}

// TestOperatorCommitDoesNotSyncWhenStandalone: on a non-cluster node the
// operator commit path must not attempt a peer push.
func TestOperatorCommitDoesNotSyncWhenStandalone(t *testing.T) {
	d, calls := newSyncProbeDaemon(t, nil)

	if _, err := d.commitAndApplyOperator(t.Context(), ""); err != nil {
		t.Fatalf("commitAndApplyOperator: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("operator commit on a standalone node must NOT sync a peer; got %d pushes", *calls)
	}
}

// TestOperatorCommitDoesNotSyncWhenNonOwner: a clustered node that does not own
// RG0 must not push (the RG0 owner is the config authority).
func TestOperatorCommitDoesNotSyncWhenNonOwner(t *testing.T) {
	d, calls := newSyncProbeDaemon(t, clusterNotOwningRG0(t))

	if _, err := d.commitAndApplyOperator(t.Context(), ""); err != nil {
		t.Fatalf("commitAndApplyOperator: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("operator commit on a non-RG0-owner must NOT sync a peer; got %d pushes", *calls)
	}
}

// TestEventEngineCommitDoesNotSyncEvenWhenRG0Owner pins the autonomous
// event-options opt-out: the engine commits with syncPeer=false directly, so
// even on an RG0 owner it must NOT push its node-local remediation to the peer.
func TestEventEngineCommitDoesNotSyncEvenWhenRG0Owner(t *testing.T) {
	d, calls := newSyncProbeDaemon(t, clusterOwningRG0(t))

	// The shape initEventEngine wires: commitAndApply with syncPeer=false.
	if _, err := d.commitAndApply(t.Context(), "", false); err != nil {
		t.Fatalf("commitAndApply(false): %v", err)
	}
	if *calls != 0 {
		t.Fatalf("the event-engine opt-out (syncPeer=false) must NOT sync the peer even on an RG0 owner; got %d pushes", *calls)
	}
}

// TestOperatorCommitConfirmedSyncsPeerWhenRG0Owner: the commit-confirmed
// operator path syncs the peer on the RG0 owner, same policy as plain commit.
func TestOperatorCommitConfirmedSyncsPeerWhenRG0Owner(t *testing.T) {
	d, calls := newSyncProbeDaemon(t, clusterOwningRG0(t))

	if _, err := d.commitConfirmedAndApplyOperator(t.Context(), 1); err != nil {
		t.Fatalf("commitConfirmedAndApplyOperator: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("operator commit-confirmed on the RG0 owner must sync the peer exactly once (#5054); got %d", *calls)
	}
}
