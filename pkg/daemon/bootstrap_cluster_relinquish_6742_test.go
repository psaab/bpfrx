package daemon

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #6742: a node that rolls back into bootstrap mode must not keep acting
// clustered while it is logically unconfigured.
//
// Before this, enterBootstrapMode tore down networkd files, FRR and the
// dataplane but never touched cluster comms — so VRRP kept advertising, the
// node could hold or win RG mastership, and it answered for the RETH VIPs with
// a dataplane the same function had just detached. The peer saw a healthy node
// throughout.
//
// The ORDER is the load-bearing property and is what these tests assert:
// resigning while this node can still forward makes the handover a planned
// failover (priority-0 burst, ~1 ms takeover); resigning after the detach would
// blackhole until the peer noticed a missing heartbeat.

// relinquish6742Daemon builds a clustered daemon whose resignation seam records
// the order of events against the dataplane teardown.
func relinquish6742Daemon(t *testing.T, rgIDs []int, barrier vipReleaseBarrier) (*Daemon, *[]string, *sync.Mutex) {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	var rgs []*config.RedundancyGroup
	for _, id := range rgIDs {
		rgs = append(rgs, &config.RedundancyGroup{ID: id, NodePriorities: map[int]int{0: 200}})
	}
	cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: rgs})

	d := &Daemon{
		applySem:              semaphore.NewWeighted(1),
		cluster:               cm,
		vrrpMgr:               vrrp.NewManager(),
		rgStates:              make(map[int]*rgStateMachine),
		rethVIPReleaseTimeout: 2 * time.Second,
		opts:                  Options{NoDataplane: true},
	}
	// Materialise the live RG state machines — the production enumeration reads
	// these, NOT the config, because the config is what the rollback discards.
	for _, id := range rgIDs {
		d.getOrCreateRGState(id)
	}

	var mu sync.Mutex
	var order []string
	d.resignRethRGFn = func(rgID int) vipReleaseBarrier {
		mu.Lock()
		order = append(order, "resign")
		mu.Unlock()
		return barrier
	}
	// The apply-body seam makes enterBootstrapMode skip the real fs / FRR /
	// dataplane teardown. Record that it was reached so the ORDER assertion has
	// a second event to order against.
	d.applyBodyForTest = func(*config.Config) {}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep {
		mu.Lock()
		order = append(order, "teardown")
		mu.Unlock()
		return nil
	}
	return d, &order, &mu
}

// TestBootstrapRollbackResignsBeforeTeardown6742 is the defect proper.
func TestBootstrapRollbackResignsBeforeTeardown6742(t *testing.T) {
	barrier := newFakeVIPRelease()
	barrier.release(nil) // VIPs already off; the wait resolves immediately.
	d, order, mu := relinquish6742Daemon(t, []int{0, 1}, barrier)

	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), *order...)
	mu.Unlock()

	if len(got) != 3 {
		t.Fatalf("expected one resign per redundancy group plus the teardown, got %v", got)
	}
	if got[0] != "resign" || got[1] != "resign" {
		t.Errorf("cluster mastership was not relinquished for every redundancy group before the "+
			"teardown: %v — a node rolling back into bootstrap kept advertising VRRP and could "+
			"hold or win RG mastership while logically unconfigured", got)
	}
	if got[2] != "teardown" {
		t.Errorf("the dataplane teardown ran BEFORE the resign (%v). Resigning after the detach "+
			"blackholes traffic for the RETH VIPs until the peer notices a missing heartbeat, "+
			"instead of handing over in ~1ms via the priority-0 burst", got)
	}
	if !d.bootstrapMode.Load() {
		t.Error("bootstrapMode not set")
	}
}

// TestBootstrapRollbackReportsAFailedResign6742 pins the honest-reporting half:
// a resign that does not complete must make the rollback DEGRADED, not clean.
// #5868 requires a partial teardown never be reported as a clean rollback, and
// a silently-swallowed resign failure is exactly that — the operator would be
// told the node is safely unconfigured while it still holds the VIPs.
func TestBootstrapRollbackReportsAFailedResign6742(t *testing.T) {
	barrier := newFakeVIPRelease()
	barrier.release(errors.New("vip release refused"))
	d, _, _ := relinquish6742Daemon(t, []int{0}, barrier)

	err := d.enterBootstrapMode()
	if err == nil {
		t.Fatal("a failed VIP release was reported as a CLEAN rollback — the operator is told the " +
			"node is safely unconfigured while it may still answer for the RETH virtual addresses")
	}
	if !errorMentions6742(err, "resign redundancy group 0") {
		t.Errorf("the rollback error does not name the failed step: %v", err)
	}
}

// TestBootstrapRollbackStandaloneIsANoOp6742 is the TIGHTENING control. A fix
// that unconditionally resigned or stopped comms would satisfy the tests above
// while breaking every standalone node's rollback. A daemon with no cluster
// manager must reach the teardown with no resign at all.
func TestBootstrapRollbackStandaloneIsANoOp6742(t *testing.T) {
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		rgStates: make(map[int]*rgStateMachine),
		opts:     Options{NoDataplane: true},
	}
	var mu sync.Mutex
	var order []string
	d.resignRethRGFn = func(int) vipReleaseBarrier {
		mu.Lock()
		order = append(order, "resign")
		mu.Unlock()
		return nil
	}
	d.applyBodyForTest = func(*config.Config) {}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep {
		mu.Lock()
		order = append(order, "teardown")
		mu.Unlock()
		return nil
	}

	// clusterCommsGen is the observable that discriminates the standalone
	// guard. Every ACTION the guard skips is independently a no-op without a
	// cluster — the RG loop finds an empty map, and stopClusterComms checks
	// d.cluster itself — so a test that only watched for a resign would pass
	// with the guard deleted. What is NOT a no-op is stopClusterComms bumping
	// the comms generation and the function logging that redundancy groups were
	// resigned, on a node that has none. Pinning the generation makes the guard
	// load-bearing against something real rather than defensive-by-assertion.
	d.clusterCommsMu.Lock()
	genBefore := d.clusterCommsGen
	d.clusterCommsMu.Unlock()

	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("standalone rollback returned an error: %v", err)
	}

	d.clusterCommsMu.Lock()
	genAfter := d.clusterCommsGen
	d.clusterCommsMu.Unlock()
	if genAfter != genBefore {
		t.Errorf("a standalone node ran the cluster-comms teardown during bootstrap rollback "+
			"(clusterCommsGen %d -> %d): it has no comms to stop, and the relinquish then "+
			"reports redundancy groups resigned on a node that has none", genBefore, genAfter)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, ev := range order {
		if ev == "resign" {
			t.Errorf("a standalone node (no cluster manager) attempted a VRRP resignation during "+
				"bootstrap rollback: %v", order)
		}
	}
	if len(order) != 1 || order[0] != "teardown" {
		t.Errorf("standalone rollback did not reach the teardown: %v", order)
	}
}

func errorMentions6742(err error, want string) bool {
	if err == nil {
		return false
	}
	return len(want) > 0 && contains6742(err.Error(), want)
}

func contains6742(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
