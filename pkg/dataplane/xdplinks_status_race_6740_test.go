package dataplane

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/link"
)

// #6740 — the 1 Hz userspace status path ranged the root Manager's xdpLinks Go
// map (and indexed the then-exported VlanSubInterfaces map) while
// CompileUserspaceShim / AttachXDP / DetachXDP mutated them. A concurrent Go map
// read+write is a fatal runtime.throw, so the status poll could kill xpfd
// outright — a crash, not a torn value.
//
// TWO LEGS, because they prove different things and neither is sufficient:
//
//   - the -race leg is BEHAVIOURAL but probabilistic: it shows the detector saw
//     no conflicting access during this run. A green there is evidence, not
//     proof, and it stays green if someone later removes the lock and the
//     scheduler happens not to interleave.
//   - the lock-ownership leg is DETERMINISTIC: it asserts the status accessor
//     actually acquires m.mu, via the muAcquireProbeHook seam. Remove the Lock
//     and it reds every time, on any scheduler.

// TestStatusPathReadRacesCompileWrite_6740 hammers the status accessor against
// the link-map writers.
//
// The writer loops until the READER signals completion rather than running a
// matching iteration count: with equal counts the cheap loop finishes inside the
// expensive one's first pass and the windows barely overlap, which is a false
// green. The observed iteration counts are logged so a future reader can see
// the overlap actually happened rather than trusting the shape of the test.
func TestStatusPathReadRacesCompileWrite_6740(t *testing.T) {
	mgr := newRaceManager6740()
	const readIters = 3000
	const writerCap = 200000 // safety bound: never spin unbounded if the reader stalls
	done := make(chan struct{})
	started := make(chan struct{})
	var writes int64

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < writerCap; i++ {
			// Signal only AFTER the first mutation, so the reader cannot begin
			// before the writer is genuinely touching the maps. Without this
			// barrier the reader's loop drained before the goroutine was ever
			// scheduled and the test reported 0 writer iterations — green
			// having exercised nothing, which is what the guard below catches.
			select {
			case <-done:
				return
			default:
			}
			ifindex := i % 64
			mgr.SetLinkForTest(ifindex, fakeLink6740{}, fakeLink6740{})
			// Drive the PRODUCTION writer, not a test-local imitation: this is
			// the CompileUserspaceShim/Compile path that mutates
			// vlanSubInterfaces under the reader.
			mgr.markVLANSubInterfaces(&CompileResult{
				genericXDPIfindexes: map[int]bool{ifindex: true},
				tunnelIfindexes:     map[int]bool{},
			})
			mgr.deleteXDPLink(ifindex)
			if atomic.AddInt64(&writes, 1) == 1 {
				close(started)
			}
			// Yield: a lock-holding writer with no yield point starves the
			// reader badly enough that the test wall-clocks out instead of
			// overlapping, which is a hang rather than a result.
			runtime.Gosched()
		}
	}()

	<-started
	for i := 0; i < readIters; i++ {
		// The exact 1 Hz status-path call. Before #6740 this ranged the live
		// map and indexed the exported VLAN map with no lock at all.
		_ = mgr.XDPEntryPrograms()
	}
	close(done)
	wg.Wait()

	w := atomic.LoadInt64(&writes)
	t.Logf("reader iterations=%d writer iterations=%d (writer ran until the reader finished, "+
		"so the windows genuinely overlap rather than the cheap loop draining first)", readIters, w)
	if w == 0 {
		t.Fatalf("the writer never ran — the two goroutines did not overlap, so this run " +
			"exercised nothing and a green result would be meaningless")
	}
}

// TestStatusAccessorTakesTheLock_6740 is the deterministic leg. It asserts that
// XDPEntryPrograms — the accessor the 1 Hz status path calls — acquires m.mu.
// Unlike the -race leg this cannot pass by scheduling luck: delete the Lock and
// the probe never fires.
func TestStatusAccessorTakesTheLock_6740(t *testing.T) {
	var sites []string
	var mu sync.Mutex
	muAcquireProbeHook = func(site string) {
		mu.Lock()
		sites = append(sites, site)
		mu.Unlock()
	}
	t.Cleanup(func() { muAcquireProbeHook = nil })

	mgr := newRaceManager6740()
	mgr.SetLinkForTest(7, fakeLink6740{}, nil)
	_ = mgr.XDPEntryPrograms()

	mu.Lock()
	defer mu.Unlock()
	for _, s := range sites {
		if s == "XDPEntryPrograms" {
			return
		}
	}
	t.Fatalf("XDPEntryPrograms did not acquire m.mu (probe sites seen: %v).\n"+
		"  The 1 Hz status path reads xdpLinks and vlanSubInterfaces; without the lock a\n"+
		"  concurrent CompileUserspaceShim/AttachXDP write is a fatal runtime.throw, and\n"+
		"  the -race leg in this file can still pass by scheduling luck.", sites)
}

// newRaceManager6740 builds a Manager with just the link bookkeeping
// initialised — no kernel state, so these legs issue no syscalls.
func newRaceManager6740() *Manager {
	return &Manager{
		xdpLinks:          make(map[int]link.Link),
		tcLinks:           make(map[int]link.Link),
		vlanSubInterfaces: make(map[int]bool),
	}
}

// fakeLink6740 is a link.Link that touches no kernel state.
type fakeLink6740 struct{ link.Link }

// TestLinkAccessorsReturnSnapshots_6740 binds the SHAPE of the fix, not just its
// effect. XDPLinks/TCLinks used to hand out the live map, which put every
// caller's range loop outside any lock the accessor could take — that is the
// root cause, and the -race leg above would not notice it coming back, because
// that leg exercises XDPEntryPrograms rather than these two accessors.
//
// It also pins the property pkg/dataplane/userspace depends on: manager_compile
// ranges XDPLinks() while calling DetachXDP for each ifindex it sees, which
// mutates the very map it would otherwise be iterating.
func TestLinkAccessorsReturnSnapshots_6740(t *testing.T) {
	mgr := newRaceManager6740()
	mgr.SetLinkForTest(11, fakeLink6740{}, fakeLink6740{})

	xdp := mgr.XDPLinks()
	tc := mgr.TCLinks()
	if len(xdp) != 1 || len(tc) != 1 {
		t.Fatalf("premise broken: seeded one link each, got xdp=%d tc=%d", len(xdp), len(tc))
	}

	// Mutating what the accessor returned must not reach the manager.
	delete(xdp, 11)
	delete(tc, 11)
	xdp[99] = fakeLink6740{}
	tc[99] = fakeLink6740{}

	if _, ok := mgr.xdpLinkFor(11); !ok {
		t.Errorf("deleting from the map XDPLinks returned removed the manager's entry — " +
			"the accessor is handing out the LIVE map again, which is the #6740 root cause")
	}
	if _, ok := mgr.tcLinkFor(11); !ok {
		t.Errorf("deleting from the map TCLinks returned removed the manager's entry — same root cause")
	}
	if _, leaked := mgr.xdpLinkFor(99); leaked {
		t.Errorf("an insertion into the returned map reached the manager's xdpLinks")
	}
	if _, leaked := mgr.tcLinkFor(99); leaked {
		t.Errorf("an insertion into the returned map reached the manager's tcLinks")
	}
}

// TestSwapTargetsReleaseTheLock_6740 binds the load-bearing half of the issue's
// second acceptance criterion — "no lock held across netlink/BPF syscalls".
//
// swapXDPEntryProg reads the link set and the VLAN skip set, then calls
// link.Update() (a BPF syscall) per interface. Holding m.mu across that loop
// would block the 1 Hz status path behind a syscall, which is the deadlock-
// adjacent shape the scoped-section rule exists to prevent. xdpSwapTargets is
// what makes that possible: it snapshots BOTH maps under one hold and RETURNS,
// so the caller's loop runs unlocked.
//
// SCOPE, stated honestly: this asserts the snapshot helper releases the lock. It
// does NOT prove the caller never takes m.mu itself — a mutation that adds an
// explicit Lock around the swap loop passes this test, and the property there is
// enforced structurally (the loop iterates a returned slice, not the maps)
// rather than by assertion. Driving the real swap loop would need a loaded BPF
// program and a link whose Update is a syscall, which this package's unit tests
// cannot provide.
func TestSwapTargetsReleaseTheLock_6740(t *testing.T) {
	mgr := newRaceManager6740()
	mgr.SetLinkForTest(3, fakeLink6740{}, nil)
	mgr.SetLinkForTest(4, fakeLink6740{}, nil)
	mgr.markVLANSubInterfaces(&CompileResult{
		genericXDPIfindexes: map[int]bool{4: true},
		tunnelIfindexes:     map[int]bool{},
	})

	targets := mgr.xdpSwapTargets()
	if !mgr.mu.TryLock() {
		t.Fatalf("xdpSwapTargets returned with m.mu still held — the swap loop's " +
			"link.Update() syscalls would run under the lock the 1 Hz status path needs")
	}
	mgr.mu.Unlock()

	// ...and the snapshot must already have applied the VLAN skip, so the
	// caller never needs to consult the maps again mid-loop.
	if len(targets) != 1 || targets[0].ifindex != 3 {
		t.Errorf("swap targets = %+v, want only ifindex 3 (4 is a VLAN sub-interface and "+
			"must be skipped inside the same lock hold that read the link set)", targets)
	}
}
