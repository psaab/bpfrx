package daemon

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

// raApplySpy records every desired set handed to ra.Apply so a test can assert
// exactly what the daemon would transmit. It stands in for the concrete
// *ra.Manager via the d.raApplyFn hook (mirrors startupGoodbyeWithdrawFn, #5093).
type raApplySpy struct {
	mu    sync.Mutex
	calls [][]*config.RAInterfaceConfig
}

func (s *raApplySpy) apply(desired []*config.RAInterfaceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy the slice header so a later in-place reuse by the caller cannot
	// mutate a recorded call.
	cp := append([]*config.RAInterfaceConfig(nil), desired...)
	s.calls = append(s.calls, cp)
	return nil
}

func (s *raApplySpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *raApplySpy) last() []*config.RAInterfaceConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return nil
	}
	return s.calls[len(s.calls)-1]
}

// appliedPrefixes flattens the prefixes of the last applied desired set.
func (s *raApplySpy) lastPrefixes() []string {
	var out []string
	for _, ra := range s.last() {
		for _, p := range ra.Prefixes {
			out = append(out, p.Prefix)
		}
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// raClusterStore builds a real config store committing a single-reth cluster
// config: reth0 in RG1 (members ge-0/0/0 node0 + ge-7/0/0 node1), unit 50 tagged
// VLAN 50, and a router-advertisement on reth0.50 advertising `prefix`. The
// resolved RA interface is "ge-0-0-0.50" (verified against rethInterfacesForRG).
func raClusterStore(t *testing.T, prefix string) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster node 0\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
			"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces reth0 unit 50 vlan-id 50\n" +
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0\n" +
			"set protocols router-advertisement interface reth0.50 prefix " + prefix + "\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigure()
	return s
}

// TestClusterRAStableActiveReappliesOnCommit is the #5861 stable-active
// regression. A day-2 RA edit (a new prefix added) on an RG that stays MASTER —
// with NO ownership transition — must re-apply RA on this active owner. Before
// #5861 the cluster commit path SKIPPED ra.Apply (RA was managed only by VRRP
// ownership events) and the reconcile loop re-applied RA only on an rg_active
// transition (`if tr.Changed`), so the primary kept advertising the OLD prefix
// set until failover/restart.
//
// The test drives the real commit entrypoint (applyServicesReconcile) so it
// binds the actual wiring: reverting the fix (deleting the
// `if isCluster { d.reconcileClusterRAServices("commit") }` call) makes the spy
// never see the new prefix on the stable-active RG → RED.
func TestClusterRAStableActiveReappliesOnCommit(t *testing.T) {
	const p1 = "2001:db8:1::/64"
	const p2 = "2001:db8:aaaa::/64" // added day-2, no ownership change

	s := raClusterStore(t, p1)
	spy := &raApplySpy{}
	d := &Daemon{
		store:     s,
		applySem:  semaphore.NewWeighted(1),
		rgStates:  make(map[int]*rgStateMachine),
		raApplyFn: spy.apply,
	}
	// This node is the CURRENT active owner of RG1 (MASTER). No transition
	// happens for the rest of the test — ownership is stable.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)

	// Initial commit while MASTER: RA senders come up advertising p1.
	if _, _ = d.applyServicesReconcile(s.ActiveConfig()); spy.count() == 0 {
		t.Fatal("initial cluster commit did not apply RA on the active owner")
	}
	if got := spy.lastPrefixes(); !contains(got, p1) {
		t.Fatalf("initial apply missing %s; got prefixes %v", p1, got)
	}
	initialCalls := spy.count()

	// Day-2 RA edit: add prefix p2. Ownership does NOT change.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set protocols router-advertisement interface reth0.50 prefix " + p2 + "\n"); err != nil {
		t.Fatalf("LoadSet day-2 edit: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit day-2 edit: %v", err)
	}
	s.ExitConfigure()

	// The commit reconcile MUST re-apply RA with the new desired set even though
	// no VRRP/cluster transition occurred (#5861 core fix).
	d.applyServicesReconcile(s.ActiveConfig())
	if spy.count() == initialCalls {
		t.Fatal("day-2 RA edit on a stable-active RG did not reach ra.Apply " +
			"(the #5861 bug — RA never re-applies without an ownership transition)")
	}
	got := spy.lastPrefixes()
	if !contains(got, p2) {
		t.Fatalf("stable-active re-apply missing the newly-added prefix %s; got %v", p2, got)
	}
	if !contains(got, p1) {
		t.Fatalf("stable-active re-apply dropped the retained prefix %s; got %v", p1, got)
	}
}

// TestClusterRADemotionRaceDoesNotTransmit is the #5861 demotion-race guard. A
// config apply that RACES a demotion — the node was MASTER for RG1 when the
// commit began but rg-state flipped to BACKUP before the RA apply — must NOT
// re-arm/transmit RA on the now-inactive node. The guard is the at-apply-time
// owner check in desiredClusterRA: the desired set is filtered by the ownership
// snapshot taken under raReconcileMu, and the demote path updates rg-state
// BEFORE it drives the RA reconcile, so under the lock the snapshot always
// reflects the true current owner.
//
// Reverting the guard (dropping the `if !active { continue }` owner filter in
// desiredClusterRA) makes the demoted node keep RG1's interface in the desired
// set → the stale senders keep transmitting → RED.
func TestClusterRADemotionRaceDoesNotTransmit(t *testing.T) {
	const p1 = "2001:db8:1::/64"
	s := raClusterStore(t, p1)
	spy := &raApplySpy{}
	d := &Daemon{
		store:     s,
		rgStates:  make(map[int]*rgStateMachine),
		raApplyFn: spy.apply,
	}

	// Node is MASTER for RG1: prime the active RA senders (advertising p1).
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	d.reconcileClusterRAServices("commit")
	if !contains(spy.lastPrefixes(), p1) {
		t.Fatalf("precondition: active owner must advertise %s; got %v", p1, spy.lastPrefixes())
	}

	// DEMOTION: rg-state flips to BACKUP (this is exactly what the VRRP demote
	// path does BEFORE it drives the RA withdraw). The commit that was in flight
	// now reaches its RA apply — but the node is no longer the owner.
	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	d.reconcileClusterRAServices("commit-racing-demotion")

	// The now-inactive node must NOT be transmitting RG1's RA. The last apply is
	// a withdraw (empty desired set), and no recorded apply after the demotion
	// carries the demoted interface.
	if got := spy.lastPrefixes(); len(got) != 0 {
		t.Fatalf("demoted node still transmitting RA prefixes %v — demotion-race "+
			"guard failed (re-armed RA on an inactive owner)", got)
	}
	for _, ra := range spy.last() {
		if ra.Interface == "ge-0-0-0.50" {
			t.Fatalf("demoted node's desired set still includes %s — the owner "+
				"gate did not drop the demoted RG", ra.Interface)
		}
	}
}
