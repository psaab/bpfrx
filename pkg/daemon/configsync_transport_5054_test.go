// #5054: REST and local-shell commits skipped peer config-sync while gRPC did
// not, so after a REST/shell commit a healthy HA cluster stayed diverged until
// an unrelated transport-disconnect reverse-sync — an RG failover could then
// silently restore config the operator believed changed.
//
// The fix makes the peer-sync decision transport-independent: all operator
// commit paths (gRPC / REST / local shell) route through commitAndApplyOperator
// / commitConfirmedAndApplyOperator, which derive the decision from RG0
// ownership (rg0ConfigSyncAuthority) rather than a per-transport constant. The
// autonomous event-options engine keeps its explicit opt-out (peerSyncNever)
// because each node fires remediation independently from its own RPM events.
//
// These tests pin (1) the pure decision function across the cluster-state table,
// (2) the behavioral outcome of the shared operator commit path — an operator
// commit syncs the peer iff this node owns RG0, a standalone / non-owner node
// does not, and the event-engine opt-out still suppresses the sync even on an
// RG0 owner — and (3) the per-transport WIRING in daemon_run.go: the gRPC / REST
// / local-shell commit closures (the grpc/rest/shell CommitFn/CommitConfirmedFn
// seams) each route through commitAndApplyOperator / commitConfirmedAndApplyOperator,
// so no single transport can silently diverge from the RG0-ownership policy.
//
// FAIL-ON-REVERT: reverting commitAndApplyOperator itself (or neutralizing
// rg0ConfigSyncAuthority to always-false) turns TestOperatorCommit* and the
// owner decision-table case RED. INDEPENDENTLY, reverting ANY ONE transport seam
// in daemon_run.go back to commitAndApply(ctx, comment, peerSyncNever) — the exact #5054
// regression — turns that transport's owner sub-case in
// TestTransportCommitFnWiringSyncsPeerByRG0Ownership /
// TestTransportCommitConfirmedFnWiringSyncsPeerByRG0Ownership RED (0 pushes on
// the RG0 owner); a hardcoded syncPeer=true reds its non-owner sub-case.
//
// The pre-#5961 decision-function / operator-path tests above did NOT cover the
// transport wiring: they invoke commitAndApplyOperator directly, so reverting a
// single transport's daemon_run.go closure left every one of them green. That is
// the coverage gap the TestTransportCommit*Wiring tests close (#5961).
package daemon

import (
	"context"
	"path/filepath"
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
//
// The committed config's topology mode MUST match the runtime HA state
// (d.cluster): the #5840 topology preflight rejects any commit whose desired
// mode disagrees with the running HA runtime, so a clustered runtime
// (cl != nil) is paired with a clustered config and a standalone probe
// (cl == nil) with a standalone one — mirroring production, where a constructed
// d.cluster always implies a clustered active config. The host-name OLD->NEW
// staged diff supplies a real intra-mode change either way, keeping the
// RG0-ownership peer-sync decision (not the topology mode) the thing under test.
func newSyncProbeDaemon(t *testing.T, cl *cluster.Manager) (*Daemon, *int) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	seed := func(step string) {
		if err := s.SetFromInput(step); err != nil {
			t.Fatalf("set %q: %v", step, err)
		}
	}
	seed("system host-name OLD")
	if cl != nil {
		seed("chassis cluster cluster-id 1")
		seed("chassis cluster authentication-key test-cluster-psk-6611")
		seed("chassis cluster node 0")
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit baseline: %v", err)
	}
	// Commit() leaves the store in configure mode with the candidate recloned
	// from active; stage the intra-mode host-name change directly.
	seed("system host-name NEW")
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
// event-options opt-out: the engine commits with peerSyncNever directly, so
// even on an RG0 owner it must NOT push its node-local remediation to the peer.
func TestEventEngineCommitDoesNotSyncEvenWhenRG0Owner(t *testing.T) {
	d, calls := newSyncProbeDaemon(t, clusterOwningRG0(t))

	// The shape initEventEngine wires: commitAndApply with peerSyncNever.
	// #5962: peerSyncNever is a POLICY, not a resolved authority answer, so it
	// stays false however ownership moves — which is the distinction the bool
	// it replaced could not express.
	if _, err := d.commitAndApply(t.Context(), "", peerSyncNever); err != nil {
		t.Fatalf("commitAndApply(false): %v", err)
	}
	if *calls != 0 {
		t.Fatalf("the event-engine opt-out (peerSyncNever) must NOT sync the peer even on an RG0 owner; got %d pushes", *calls)
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

// syncByOwnershipCases is the shared per-transport wiring table: an operator
// commit must sync the peer IFF this node owns RG0, on every transport. The
// owner case reds a transport reverted to a hardcoded peerSyncNever (the #5054
// regression); the non-owner / standalone cases red a hardcoded syncPeer=true.
var syncByOwnershipCases = []struct {
	name    string
	cluster func(*testing.T) *cluster.Manager
	want    int
}{
	{"rg0-owner", clusterOwningRG0, 1},
	{"non-owner", clusterNotOwningRG0, 0},
	{"standalone", func(*testing.T) *cluster.Manager { return nil }, 0},
}

// TestTransportCommitFnWiringSyncsPeerByRG0Ownership drives the EXACT commit
// closures wired into the gRPC / REST / local-shell servers in daemon_run.go
// (grpcCommitFn / restCommitFn / shellCommitFn) and asserts each resolves
// peer-sync by RG0 ownership, never a per-transport constant. This is the
// coverage the decision-function tests above lack: a single-transport wiring
// regression turns exactly one sub-case RED here instead of staying silent.
func TestTransportCommitFnWiringSyncsPeerByRG0Ownership(t *testing.T) {
	transports := []struct {
		name string
		fn   func(*Daemon) func(context.Context, string) (*config.Config, error)
	}{
		{"grpc", (*Daemon).grpcCommitFn},
		{"rest", (*Daemon).restCommitFn},
		{"shell", (*Daemon).shellCommitFn},
	}
	for _, tr := range transports {
		for _, tc := range syncByOwnershipCases {
			t.Run(tr.name+"/"+tc.name, func(t *testing.T) {
				d, calls := newSyncProbeDaemon(t, tc.cluster(t))
				if _, err := tr.fn(d)(t.Context(), ""); err != nil {
					t.Fatalf("%s CommitFn: %v", tr.name, err)
				}
				if *calls != tc.want {
					t.Fatalf("%s CommitFn on %s: peer syncs = %d, want %d — the transport wiring must route through commitAndApplyOperator, not a hardcoded syncPeer (#5054/#5961)", tr.name, tc.name, *calls, tc.want)
				}
			})
		}
	}
}

// TestTransportCommitConfirmedFnWiringSyncsPeerByRG0Ownership is the
// commit-confirmed analogue: the gRPC / REST / local-shell CommitConfirmedFn
// closures (grpcCommitConfirmedFn / restCommitConfirmedFn / shellCommitConfirmedFn)
// must route through commitConfirmedAndApplyOperator so `commit confirmed` obeys
// the same transport-independent RG0-ownership peer-sync policy.
func TestTransportCommitConfirmedFnWiringSyncsPeerByRG0Ownership(t *testing.T) {
	transports := []struct {
		name string
		fn   func(*Daemon) func(context.Context, int) (*config.Config, error)
	}{
		{"grpc", (*Daemon).grpcCommitConfirmedFn},
		{"rest", (*Daemon).restCommitConfirmedFn},
		{"shell", (*Daemon).shellCommitConfirmedFn},
	}
	for _, tr := range transports {
		for _, tc := range syncByOwnershipCases {
			t.Run(tr.name+"/"+tc.name, func(t *testing.T) {
				d, calls := newSyncProbeDaemon(t, tc.cluster(t))
				if _, err := tr.fn(d)(t.Context(), 1); err != nil {
					t.Fatalf("%s CommitConfirmedFn: %v", tr.name, err)
				}
				if *calls != tc.want {
					t.Fatalf("%s CommitConfirmedFn on %s: peer syncs = %d, want %d — the transport wiring must route through commitConfirmedAndApplyOperator, not a hardcoded syncPeer (#5054/#5961)", tr.name, tc.name, *calls, tc.want)
				}
			})
		}
	}
}
