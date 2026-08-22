package daemon

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestReconcileProxyARP_SweepsPriorInterface is the #4955 daemon-side
// fail-on-revert: when a commit REMOVES proxy-arp, the daemon must still drive
// the dataplane reconcile and feed it the interfaces a prior commit installed
// proxy-arp on, so their orphaned NTF_PROXY entries get swept. Before the fix
// the daemon skipped the dataplane reconcile entirely on full removal (it ran
// only the #2475 sysctl teardown), so the neighbor entries were never deleted.
//
// The dataplane reconcile is stubbed through the proxyARPApplyFn seam so the
// test asserts the prior-interface set is passed through without needing
// netlink. Fail-on-revert: the pre-fix daemon never calls proxyARPApplyFn on
// full removal, so gotPrior stays nil and the ge-0-0-1→11 assertion fails.
func TestReconcileProxyARP_SweepsPriorInterface(t *testing.T) {
	withFakeIfaceResolver(t, map[string]int{"ge-0-0-1": 11})

	var applyCalled bool
	var gotPrior map[string]int
	prevApply := proxyARPApplyFn
	proxyARPApplyFn = func(_ *config.Config, _, priorIfaceMap map[string]int, _ map[int]string) ([]dataplane.ProxyARPAdded, map[string]map[int]struct{}, error) {
		applyCalled = true
		gotPrior = priorIfaceMap
		return nil, map[string]map[int]struct{}{}, nil
	}
	t.Cleanup(func() { proxyARPApplyFn = prevApply })

	prevDisable := proxyARPDisableFn
	proxyARPDisableFn = func(_ map[string]map[int]struct{}) int { return 0 }
	t.Cleanup(func() { proxyARPDisableFn = prevDisable })

	d := &Daemon{}
	// A prior commit installed proxy-arp on ge-0-0-1 (Linux netdev name key,
	// as ReconcileProxyARP records via link.Attrs().Name).
	d.proxyARPEnabled = map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET: {}},
	}

	// New commit removes proxy-arp entirely.
	d.reconcileProxyARP(&config.Config{})

	if !applyCalled {
		t.Fatal("reconcileProxyARP did not drive the dataplane reconcile on full " +
			"removal — orphaned NTF_PROXY entries never swept (#4955)")
	}
	if gotPrior["ge-0-0-1"] != 11 {
		t.Fatalf("reconcile passed priorIfaceMap = %v, want ge-0-0-1→11 so the "+
			"orphaned NTF_PROXY entry on the removed interface is swept", gotPrior)
	}
}

// TestPriorProxyARPIfaceMap resolves prior Linux netdev names to ifindexes and
// skips names whose netdev no longer exists (nothing left to sweep there).
func TestPriorProxyARPIfaceMap(t *testing.T) {
	withFakeIfaceResolver(t, map[string]int{"ge-0-0-1": 11, "ge-0-0-2": 22})

	got := priorProxyARPIfaceMap([]string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-gone"})
	if len(got) != 2 || got["ge-0-0-1"] != 11 || got["ge-0-0-2"] != 22 {
		t.Fatalf("priorProxyARPIfaceMap = %v, want {ge-0-0-1:11, ge-0-0-2:22} "+
			"(unresolvable name skipped)", got)
	}
}
