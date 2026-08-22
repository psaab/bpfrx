package daemon

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/vrrp"
)

// keaApplyRecorder is a systemctl seam that always fails the reconcile
// shell-out, counts attempts, and holds the FIRST attempt open until the test
// releases it.
//
// Holding attempt 1 open is what makes the sequencing deterministic rather
// than a race, and it is faithful: a real Kea apply shells out to systemctl
// under a 15s bound, so it routinely outlives the reconcile pass that enqueued
// it. With it held, the pass that drove the RG-transition edge finishes while
// its apply is still in flight — so that pass's own converger call sees no
// failure and cannot consume the retry window the NEXT pass is being tested
// for. (It also pins the lock split: the apply body holds the manager's apply
// mutex for its whole duration, so a converger predicate guarded by that same
// mutex would deadlock the reconcile pass here instead of returning.)
type keaApplyRecorder struct {
	mu       sync.Mutex
	attempts int

	release chan struct{}
	done    chan int
}

func newKeaApplyRecorder() *keaApplyRecorder {
	return &keaApplyRecorder{release: make(chan struct{}), done: make(chan int, 64)}
}

func (k *keaApplyRecorder) run(args ...string) error {
	// Count only the reconcile shell-outs, so "attempt N" means "apply N".
	if len(args) == 0 || (args[0] != "restart" && args[0] != "stop") {
		return nil
	}
	k.mu.Lock()
	k.attempts++
	n := k.attempts
	k.mu.Unlock()

	if n == 1 {
		<-k.release
	}
	select {
	case k.done <- n:
	default:
	}
	return errors.New("systemctl restart kea-dhcp4: injected failure")
}

func (k *keaApplyRecorder) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.attempts
}

// quiesce waits until the attempt count stops moving, i.e. the async apply
// worker has drained its mailbox.
func (k *keaApplyRecorder) quiesce(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := -1
	stable := 0
	for time.Now().Before(deadline) {
		n := k.count()
		if n == last {
			if stable++; stable >= 5 {
				return n
			}
		} else {
			last, stable = n, 0
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Kea apply attempts never settled (last=%d)", last)
	return 0
}

// dhcpConvergerClusterSet is one RETH in RG1 with a dhcp-local-server group
// bound to its untagged unit, so the master-RG filter keeps the group while
// RG1 is MASTER.
var dhcpConvergerClusterSet = []string{
	"set system dataplane-type userspace",
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key test-cluster-psk-6535",
	"set chassis cluster redundancy-group 1 node 0 priority 200",
	"set interfaces reth1 redundant-ether-options redundancy-group 1",
	"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
	"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
	"set system services dhcp-local-server group g1 interface reth1.0",
	"set system services dhcp-local-server group g1 dhcp-attributes subnet 10.0.61.0/24",
}

func newDHCPConvergerDaemon(t *testing.T, km *dhcpserver.Manager) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, dhcpConvergerClusterSet)
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	if !cm.IsLocalPrimary(1) {
		t.Fatal("fixture: node 0 must be primary for RG1, or the MASTER edge never applies Kea")
	}
	return &Daemon{
		rgStates:   make(map[int]*rgStateMachine),
		cluster:    cm,
		store:      store,
		vrrpMgr:    vrrp.NewManager(),
		dhcpServer: km,
	}
}

func newTestKeaManager(t *testing.T, run func(...string) error) *dhcpserver.Manager {
	t.Helper()
	dir := t.TempDir()
	return dhcpserver.NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		run,
		func(string) bool { return true }, // unit already active → restart, not skip
	)
}

// #6535: in cluster mode the Kea applier is driven ONLY from the RG-transition
// edge (applyRethServicesForRG / clearRethServicesForRG, both under
// `if tr.Changed`, and applyDirectVIPOwnership's ownership edge) or an
// operator commit. There was no periodic converger, and the async apply worker
// does not retry — it logs the error and drops it. So a failover whose Kea
// apply failed leaves the wrong node serving: persistent dual-DHCP, or no DHCP
// at all, until the next RG transition or commit. Neither happens on its own.
//
// This drives real reconcile passes end to end. The retry must come from a
// LATER pass whose transition did NOT change — with tr.Changed false and no
// ownership edge, only the converger can carry it.
func TestFailedKeaApplyIsRetriedByReconcileConverger(t *testing.T) {
	rec := newKeaApplyRecorder()
	d := newDHCPConvergerDaemon(t, newTestKeaManager(t, rec.run))

	// Pass A: the RG transition edge fires and enqueues the Kea apply, which
	// is still blocked inside systemctl when the pass returns.
	d.reconcileRGState()
	if got := rec.count(); got != 1 {
		t.Fatalf("fixture: want exactly 1 Kea apply in flight after the edge pass, got %d", got)
	}

	close(rec.release)
	settled := rec.quiesce(t)
	if !d.ApplyFailedForTestingDHCP() {
		t.Fatalf("fixture: %d apply attempt(s) ran but the manager did not record a failure", settled)
	}

	// Pass B: no RG transition — cluster and VRRP state are unchanged, and
	// ownership was already claimed in pass A, so every edge is quiet.
	d.reconcileRGState()
	after := rec.quiesce(t)
	if after <= settled {
		t.Fatalf("no Kea apply on the pass after the failure (attempts=%d, was %d): a failed "+
			"apply is lost and the wrong node keeps serving DHCP until the next failover",
			after, settled)
	}

	// Pass C, immediately: the retry is spaced, not run on every 2s tick. A
	// permanently broken Kea must not be held in a continuous systemctl
	// restart loop.
	d.reconcileRGState()
	if got := rec.quiesce(t); got != after {
		t.Errorf("the converger re-drove systemctl on the very next tick: %d attempts, want %d",
			got, after)
	}
}

// TestClaimApplyRetryOnlyAfterAFailedApply pins the converger's predicate:
// nothing to do when no apply has run, nothing to do after a SUCCESSFUL apply,
// and a spaced retry after a failed one.
func TestClaimApplyRetryOnlyAfterAFailedApply(t *testing.T) {
	var fail bool
	km := newTestKeaManager(t, func(...string) error {
		if fail {
			return errors.New("systemctl restart kea-dhcp4: injected failure")
		}
		return nil
	})
	d := newDHCPConvergerDaemon(t, km)
	d.getOrCreateRGState(1).SetVRRP("reth1", true)

	now := time.Now()
	if km.ClaimApplyRetry(now) {
		t.Fatal("a manager that has never applied anything must not claim a retry")
	}

	desired := d.desiredClusterDHCPConfig(d.store.ActiveConfig())
	if desired == nil {
		t.Fatal("fixture: the master-RG filter dropped everything, so no apply can fail")
	}

	// A SUCCESSFUL apply leaves nothing to converge.
	if err := km.ApplyClusterCommit(desired); err != nil {
		t.Fatalf("fixture: the succeeding apply returned %v", err)
	}
	if km.ClaimApplyRetry(now) {
		t.Error("a retry was claimed after a successful apply — the converger would " +
			"restart Kea on a node that is already correct")
	}

	// A failed one is the debt the converger consumes.
	fail = true
	if err := km.ApplyClusterCommit(desired); err == nil {
		t.Fatal("fixture: the injected systemctl failure did not surface as an apply error")
	}
	if !km.ClaimApplyRetry(now) {
		t.Fatal("the first claim after a failed apply must be granted immediately — a " +
			"transient failure should heal on the very next reconcile tick")
	}
	if km.ClaimApplyRetry(now.Add(2 * time.Second)) {
		t.Error("a second claim one tick later was granted: a permanently broken Kea " +
			"would be re-driven through systemctl every 2s")
	}
	if !km.ClaimApplyRetry(now.Add(time.Minute)) {
		t.Error("the claim was still refused a minute later: a failed apply must " +
			"eventually be retried")
	}

	// And a later success closes the debt.
	fail = false
	if err := km.ApplyClusterCommit(desired); err != nil {
		t.Fatalf("fixture: the recovering apply returned %v", err)
	}
	if km.ClaimApplyRetry(now.Add(time.Hour)) {
		t.Error("the debt survived a successful apply: the converger would keep " +
			"restarting a healthy Kea forever")
	}
}

// ApplyFailedForTestingDHCP is a readability shim over the manager seam.
func (d *Daemon) ApplyFailedForTestingDHCP() bool {
	return d.dhcpServer.ApplyFailedForTesting()
}
