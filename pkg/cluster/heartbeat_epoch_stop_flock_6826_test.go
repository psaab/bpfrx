package cluster

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6826: what does a RETURNED Manager.Stop imply about the cross-process epoch
// flock?
//
// Manager.Stop joins the boot-epoch refinement worker with a bounded budget
// (bootEpochStopJoinBudget) and, on timeout, warns and returns. The worker is
// not cancelled — withEpochFileLock has already taken LOCK_EX and defers its
// release until after the callback's durable write and fsync, so a Stop whose
// budget expires mid-callback returns to its caller while a lock that OTHER
// PROCESSES can see is still held.
//
// That matters here rather than in general because restart is the documented
// recovery path for this subsystem: a day-2 chassis-cluster topology or
// identity change is REFUSED at commit and requires a process restart
// (pkg/daemon/cluster_topology_preflight.go). The incoming process is exactly
// the party positioned to find the outgoing one's lock still held.
//
// The behaviour was documented but never pinned, so it could drift either way
// unnoticed. These cells pin it.

// tryEpochFlock reports whether the epoch lock at path can be taken RIGHT NOW
// by an independent open file description.
//
// A second os.OpenFile creates a separate open file DESCRIPTION, and flock(2)
// associates a lock with the description rather than the process — so this
// contends with a lock held elsewhere in this same process exactly as another
// process would. The cell below asserts that property directly rather than
// assuming it, because the whole test is worthless if it does not hold.
func tryEpochFlock(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return true
}

// TestSecondDescriptionContendsWithAHeldEpochFlock6826 is the ground-truth
// control for the cells below. If a second description did NOT contend, every
// "the lock is free" assertion in this file would pass vacuously.
func TestSecondDescriptionContendsWithAHeldEpochFlock6826(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epoch")
	if !tryEpochFlock(t, path) {
		t.Fatal("setup: an unheld epoch lock must be takeable")
	}
	held, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("hold LOCK_EX: %v", err)
	}
	if tryEpochFlock(t, path) {
		t.Fatal("a second open file description must NOT be able to take a held " +
			"LOCK_EX — without this every lock-availability assertion in this file " +
			"passes for the wrong reason")
	}
	_ = unix.Flock(int(held.Fd()), unix.LOCK_UN)
	if !tryEpochFlock(t, path) {
		t.Fatal("the lock must be takeable again once released")
	}
}

// parkWorkerHoldingEpochFlock installs an epochFlock seam that takes the REAL
// lock and then parks the worker while holding it, which is the state #6826 is
// about. Returns a channel closed once the worker is parked, and an unpark.
//
// The park is deliberately AFTER origFlock rather than before it. An existing
// test in this package parks BEFORE, which holds the worker outside the lock;
// that is the right shape for its question and the wrong shape for this one.
func parkWorkerHoldingEpochFlock(t *testing.T) (parked <-chan struct{}, unpark func()) {
	t.Helper()
	at := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	orig := epochFlock
	epochFlock = func(fd int, how int) error {
		err := orig(fd, how) // take the real LOCK_EX first
		once.Do(func() {
			close(at)
			<-release
		})
		return err
	}
	t.Cleanup(func() { epochFlock = orig })
	var unparkOnce sync.Once
	unpark = func() { unparkOnce.Do(func() { close(release) }) }
	t.Cleanup(unpark)
	return at, unpark
}

// TestStopReturnsWhileEpochFlockIsStillHeld6826 is the defect, pinned.
//
// This asserts the CURRENT contract, which is "a returned Stop does NOT imply
// the flock is released". It is written this way on purpose: the invariant
// recorded at the lock site says exactly that, and a test that asserted the
// opposite would be asserting a fix nobody has made. If someone later makes
// Stop imply release, this cell reds and points at the invariant comment — which
// is the drift-detection the issue asked for, in whichever direction it drifts.
func TestStopReturnsWhileEpochFlockIsStillHeld6826(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	parked, unpark := parkWorkerHoldingEpochFlock(t)

	m := NewManager(0, 42)
	_ = m.heartbeatBootEpoch() // spawns the refinement worker

	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("the refinement worker never reached the file lock")
	}

	// The worker is now inside withEpochFileLock holding LOCK_EX. Stop's join
	// budget cannot be met, so it must time out and return.
	stopped := make(chan struct{})
	go func() { m.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(bootEpochStopJoinBudget + 30*time.Second):
		t.Fatal("Stop did not return — the bounded join is the whole point of " +
			"bootEpochStopJoinBudget; an unbounded one parks shutdown behind a wedged store")
	}

	if tryEpochFlock(t, path) {
		t.Fatal("#6826: the epoch flock was FREE after a timed-out Stop returned. " +
			"That is a stronger guarantee than the code makes — withEpochFileLock " +
			"defers LOCK_UN until after the callback's durable write and fsync, and " +
			"nothing cancels the worker. If this became true deliberately, update the " +
			"invariant at withEpochFileLock and at joinBootEpochRefine to say so.")
	}

	// Drain before returning. The worker is still parked holding the lock and
	// the fd; letting the test return here races t.TempDir's RemoveAll against
	// the worker's write and fails cleanup with "directory not empty". Joining
	// here is NOT the assertion — that was made above, against the timed-out
	// Stop — it is teardown.
	unpark()
	if !m.joinBootEpochRefine(30 * time.Second) {
		t.Error("teardown: the unparked worker never exited")
	}
}

// TestIncomingProcessDeclinesRatherThanBlocking6826 is the other half of the
// invariant: given that a returned Stop does not imply the lock is free, an
// INCOMING process must not park behind it.
//
// Holds the lock from an independent open file description — the outgoing
// process's still-running worker — and requires withEpochFileLock to give up
// within its budget and DECLINE, rather than block until the holder releases.
//
// The assertion is on ELAPSED TIME against the budget, not on a bare
// "it returned": a blocking LOCK_EX would also return here, just after the
// holder let go, so a cell that only checked completion would pass on the
// pre-fix code.
func TestIncomingProcessDeclinesRatherThanBlocking6826(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "epoch")

	held, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("hold LOCK_EX: %v", err)
	}

	ran := false
	start := time.Now()
	withEpochFileLock(path, func() { ran = true })
	elapsed := time.Since(start)

	if ran {
		t.Fatal("#6826: the callback RAN while another description held LOCK_EX — " +
			"withEpochFileLock must not proceed without the lock")
	}
	// Generous ceiling: the point is that it gave up on its own rather than
	// waiting for a release that never came in this test.
	if elapsed > bootEpochLockAcquireBudget*3 {
		t.Errorf("#6826: waited %v for a contended lock, budget is %v — an incoming "+
			"process must decline rather than park behind an outgoing one's worker",
			elapsed, bootEpochLockAcquireBudget)
	}
	// Non-vacuity: it must actually have WAITED, not skipped the attempt.
	if elapsed < bootEpochLockRetryInterval {
		t.Errorf("#6826: returned in %v, faster than one retry interval (%v) — the "+
			"bounded wait must actually retry, or a lock released microseconds later "+
			"is needlessly declined", elapsed, bootEpochLockRetryInterval)
	}
	_ = unix.Flock(int(held.Fd()), unix.LOCK_UN)
}

// TestContendedEpochLockAcquireIsRaceFree6826 is the -race probe, shaped so it
// cannot report a false green.
//
// THE OBVIOUS SHAPE IS A FALSE GREEN. A contender loop and an acquirer loop
// with EQUAL iteration counts lets the cheap side finish inside the expensive
// side's first pass, so the two barely overlap and -race observes almost
// nothing while the test reports success. Here the acquirer is the expensive
// side (it waits out a retry interval at minimum), so the contender loops until
// the acquirer signals done rather than a fixed count, and the achieved
// contention RATE is reported so a run that degenerated to no overlap is
// visible instead of silently passing.
func TestContendedEpochLockAcquireIsRaceFree6826(t *testing.T) {
	if testing.Short() {
		t.Skip("contention probe: -short")
	}
	path := filepath.Join(t.TempDir(), "epoch")

	done := make(chan struct{})
	var contentions int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
			if err != nil {
				return
			}
			if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
				atomic.AddInt64(&contentions, 1)
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			}
			_ = f.Close()
		}
	}()

	const acquires = 40
	ran := 0
	start := time.Now()
	for i := 0; i < acquires; i++ {
		withEpochFileLock(path, func() { ran++ })
	}
	elapsed := time.Since(start)
	close(done)
	wg.Wait()

	if ran != acquires {
		t.Errorf("only %d/%d acquisitions ran their callback — an uncontended lock "+
			"must always be takeable", ran, acquires)
	}
	got := atomic.LoadInt64(&contentions)
	rate := float64(got) / elapsed.Seconds()
	t.Logf("contention probe: %d acquisitions in %v, contender completed %d "+
		"lock cycles (%.0f/s)", acquires, elapsed, got, rate)
	if got == 0 {
		t.Error("the contender never took the lock once — the two sides did not " +
			"overlap, so -race observed nothing and this probe proved nothing")
	}
}
