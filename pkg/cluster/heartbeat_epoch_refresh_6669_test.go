package cluster

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #6669 fold round 8 — the boot-epoch state lock does NOT order incarnations,
// and the recoverable half of that.
//
// withEpochFileLock serializes read-modify-write across processes, and its
// rationale used to claim that this stops two overlapping incarnations
// publishing epochs "that are not strictly ordered". It does not: it serializes
// by LOCK ACQUISITION, and heartbeatBootEpoch deliberately publishes the
// wall-clock seed and starts emitting BEFORE its worker reaches the lock, so the
// two orders are independent.
//
// These pin both halves — the mis-ordering itself (characterization, so the
// comment cannot drift back), and the recovery that keeps it from lasting for
// the life of the process.

// waitBootEpochIdle joins whatever refine worker is in flight. claimBootEpochRefine
// takes the in-flight bit on the CALLER's goroutine before the worker is
// spawned, so a caller that has just requested a refine cannot observe idle too
// early.
//
// It waits for the WHOLE word to reach 0, which is both bits: a pass owed but
// not yet started is not idle. It then joins the worker goroutine itself.
// Clearing the word is the worker's last touch of Manager state, but the
// goroutine has not necessarily RETURNED at that instant, and a test whose
// t.Cleanup restores a package var the worker reads (epochFlock,
// epochNowNanos, epochRefineBeforeRelease) races it if it only polls.
func waitBootEpochIdle(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for m.bootEpochRefine.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a boot-epoch refine worker never finished")
		}
		time.Sleep(time.Millisecond)
	}
	if !m.joinBootEpochRefine(5 * time.Second) {
		t.Fatal("the boot-epoch refine worker goroutine never exited")
	}
}

// awaitFirstRefine waits for the FIRST refine attempt to finish and then DRAINS
// the worker. Every test that cares about the first attempt should use this.
//
// bootEpochReady IS NOT A DRAIN and never was. startBootEpochRefine closes it
// as soon as the first pass returns, and the worker then goes on to call
// releaseBootEpochRefine — which reads the epochRefineBeforeRelease package var
// — and may run further coalesced passes before it exits. A test that stops at
// the channel therefore RETURNS with that worker still live, and the next test
// in the package assigns the seams it is reading.
//
// That is not hypothetical, and it is not a one-off:
//
//	go test -race ./pkg/cluster \
//	  -run 'Test(HeldFlockCannotCauseFalsePeerDeath_6169|LateRefineRequestIsReclaimed_6669)$' \
//	  -count=100
//
// reported a WRITE of epochRefineBeforeRelease by the second test against a READ
// of it by the first test's escaped worker, inside releaseBootEpochRefine.
//
// The same confusion had already been fixed twice by hand — in
// TestInitHeartbeatEpochStateNeverBlocks_6169 (the worker vs epochNowNanos) and
// in startedIncarnation — each time only at the site where it had been caught,
// which is why it was still live in five others. It lives here now so the next
// test cannot re-derive it. Eleven sites hand-rolled the bare receive. Five had
// nothing else joining the worker at all and so returned with a live one —
// TestHeldFlockCannotCauseFalsePeerDeath_6169,
// TestStartHeartbeatReturnsWithAUsableEpoch_6169, both subtests of
// TestHeartbeatBootEpochRefinementCompletes_6169, and
// TestBootEpochNeverBlocksOnStorage_6169. The rest survived only because
// keyedEpochManager registers a t.Cleanup join behind them, which is a backstop
// and not a reason to skip the drain.
func awaitFirstRefine(t *testing.T, m *Manager, what string) {
	t.Helper()
	select {
	case <-m.bootEpochReady:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the first boot-epoch refine attempt never completed", what)
	}
	waitBootEpochIdle(t, m)
}

// readPersistedEpoch reads the boot-epoch state file.
func readPersistedEpoch(t *testing.T, path string) uint64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted epoch: %v", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatalf("parse persisted epoch %q: %v", data, err)
	}
	return n
}

// keyedManagerAt installs a control-link PSK so the epoch path engages, and
// points the package path var at a per-test file.
func keyedEpochManager(t *testing.T, path string) *Manager {
	t.Helper()
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	m := NewManager(0, 42)
	m.mu.Lock()
	m.controlAuthKey = []byte("cluster-shared-secret")
	m.mu.Unlock()
	// Backstop the worker's lifetime against this test's teardown. The refine
	// worker writes under `path`, which is a t.TempDir the harness removes, and
	// reads package vars a test may have overridden. Registered here so it runs
	// after the seam restores (t.Cleanup is LIFO) and still before t.TempDir's
	// own removal, which was registered earlier by the caller.
	t.Cleanup(func() { m.joinBootEpochRefine(5 * time.Second) })
	return m
}

// TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669 is the executable
// statement of what the lock does and does not buy.
//
// The schedule is the one SO_REUSEPORT makes reachable — two overlapping xpfd
// instances, no pidfile — with the OLDER incarnation's refine worker delayed
// past the newer one's:
//
//   - B (newer, higher seed) publishes, locks first, persists `b`;
//   - A (older, lower seed) locks second, reads `b`, and raises ITSELF to `b+1`,
//     because from inside refineBootEpoch a concurrent incarnation's value and a
//     predecessor's value after a backward clock step are the same file;
//   - the peer latches `b+1` from the OLDER incarnation and refuses the NEWER
//     one, which is the survivor.
//
// The first half is a CHARACTERIZATION: it is not fixed here, and cannot be with
// this file alone (see withEpochFileLock). The second half IS the fix — B can
// re-refine at its next heartbeat start and climb back above the file, instead
// of being pinned below the peer's floor for the life of the process by a
// one-shot sync.Once.
//
// RED-on-revert: drop the `m.bootEpoch.Load() != 0 -> m.refreshBootEpoch()`
// branch in initHeartbeatEpochState (so every call funnels back through
// heartbeatBootEpoch's sync.Once) and the recovery assertion below fails with
// B still parked at its original epoch.
func TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	mB := keyedEpochManager(t, path)

	// --- B: the NEWER incarnation. It reaches the lock first and persists.
	mB.initHeartbeatEpochState()
	awaitFirstRefine(t, mB, "B's first refine")
	b := mB.heartbeatBootEpoch()
	if b == 0 {
		t.Fatal("B published no epoch")
	}
	if got := readPersistedEpoch(t, path); got != b {
		t.Fatalf("persisted %d after B's first refine, want %d", got, b)
	}

	// --- A: an OLDER incarnation (seed one second behind B's) whose worker was
	// delayed and only now reaches the lock.
	var pubA atomic.Uint64
	pubA.Store(b - uint64(time.Second))
	refineBootEpoch(path, &pubA, 0)

	epochA := pubA.Load()
	if epochA <= b {
		t.Fatalf("A published %d, which does not exceed B's %d — the schedule this test "+
			"describes did not happen, so the assertions below prove nothing", epochA, b)
	}

	// --- The peer orders them by epoch alone, so the OLDER one wins and the
	// survivor is refused.
	var peer heartbeatAuthState
	if !peer.admitAuthed(true, epochA, 0xA669, 1) {
		t.Fatal("the peer refused A's frame")
	}
	if peer.admitAuthed(true, b, 0xB669, 1) {
		t.Fatalf("the peer admitted B at %d under a floor of %d; the mis-ordering this test "+
			"characterizes is not reachable and withEpochFileLock's ordering note is stale",
			b, peer.peerEpochFloor())
	}

	// --- A exits. B's next heartbeat start (a VRF rebind, an HA comms restart,
	// or any StartHeartbeat) re-runs refinement and lifts it back above the file.
	mB.initHeartbeatEpochState()
	waitBootEpochIdle(t, mB)

	recovered := mB.heartbeatBootEpoch()
	if recovered <= epochA {
		t.Fatalf("B is still at %d after a heartbeat restart, at or below the %d the older "+
			"incarnation left in the file. Refinement behind sync.Once alone never re-reads, "+
			"so the peer refuses this node until a full daemon restart.", recovered, epochA)
	}
	if !peer.admitAuthed(true, recovered, 0xB66A, 1) {
		t.Fatalf("B at %d is still refused under floor %d after re-refinement",
			recovered, peer.peerEpochFloor())
	}
	if got := readPersistedEpoch(t, path); got != recovered {
		t.Fatalf("persisted %d after B's re-refine, want %d", got, recovered)
	}
}

// TestBootEpochRefreshIsIdempotent_6669 is the other half of making refinement
// re-runnable: on a healthy node it must be a no-op.
//
// Refinement raises whenever the persisted value is at or above what we
// published — that is how a backward clock step is carried across a restart —
// and after a successful persist the file holds OUR OWN value. So a re-run meets
// that condition trivially and would ratchet the epoch by one on every heartbeat
// start, rewriting the file each time, if nothing distinguished "the file moved
// under me" from "the file holds what I wrote".
//
// RED-on-revert: delete the `prev == lastWrote` early return in refineBootEpoch
// and the epoch climbs by one per restart here.
func TestBootEpochRefreshIsIdempotent_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	m.initHeartbeatEpochState()
	awaitFirstRefine(t, m, "the first refine")
	first := m.heartbeatBootEpoch()
	firstFile := readPersistedEpoch(t, path)

	for i := 0; i < 5; i++ {
		m.initHeartbeatEpochState()
		waitBootEpochIdle(t, m)
		if got := m.heartbeatBootEpoch(); got != first {
			t.Fatalf("restart %d moved the published epoch from %d to %d; a healthy node's "+
				"routine heartbeat restarts must not ratchet it", i, first, got)
		}
		if got := readPersistedEpoch(t, path); got != firstFile {
			t.Fatalf("restart %d rewrote the state file from %d to %d", i, firstFile, got)
		}
	}
}

// TestBootEpochSeedResolutionIsFinerThanARestart_6669 pins the seed's own
// granularity, which nothing else in the package did.
//
// pkg/cluster/README.md states the resolution as a design property ("Resolution
// is NANOSECONDS deliberately: a coarser seed hands two incarnations starting in
// the same interval identical values"), and it carries real weight in exactly
// the case persistence cannot help: two back-to-back incarnations whose writes
// do not land — a wedged or read-only store — are ordered by the seed alone.
// TestBootEpochMonotonic_6169/restarts_strictly_increase looks like the guard
// for it and is not: every iteration there persists, so `persisted+1` supplies
// strictness whenever the seed does not. Verified by rounding bootEpochSeed up
// to whole seconds — the whole package stayed green.
//
// The bar is a granularity FINER THAN A MILLISECOND rather than exactly one
// nanosecond, because that is what can be measured without flaking: consecutive
// time.Now() calls are tens of nanoseconds apart, so the smallest positive gap
// over many samples lands far below a millisecond, while any seed quantised to
// milliseconds or coarser can only produce gaps of 0 or >= 1ms. A millisecond is
// also the operationally meaningful line — two daemon starts inside one
// millisecond is a supervisor restart loop, not a contrived case.
//
// RED-on-revert: quantise bootEpochSeed to any unit >= 1ms.
func TestBootEpochSeedResolutionIsFinerThanARestart_6669(t *testing.T) {
	const samples = 2000
	seeds := make([]uint64, 0, samples)
	for i := 0; i < samples; i++ {
		seeds = append(seeds, bootEpochSeed())
	}

	smallest := uint64(0)
	for i := 1; i < len(seeds); i++ {
		if seeds[i] < seeds[i-1] {
			t.Fatalf("bootEpochSeed went BACKWARDS between samples %d and %d (%d -> %d)",
				i-1, i, seeds[i-1], seeds[i])
		}
		gap := seeds[i] - seeds[i-1]
		if gap == 0 {
			continue
		}
		if smallest == 0 || gap < smallest {
			smallest = gap
		}
	}
	if smallest == 0 {
		t.Fatalf("all %d seeds were identical — bootEpochSeed cannot distinguish two "+
			"incarnations at all", samples)
	}
	if smallest >= uint64(time.Millisecond) {
		t.Fatalf("the smallest positive gap between %d consecutive bootEpochSeed values is %v. "+
			"The seed is quantised at or above a millisecond, so two incarnations starting in "+
			"the same tick get the SAME epoch — and when persistence is unavailable that is the "+
			"only term ordering them.", samples, time.Duration(smallest))
	}
}

// TestBootEpochRefreshCarriesABackwardClockStep_6669 guards the property the
// idempotence rule must NOT break: a genuine predecessor value in the file is
// still chained from on a first pass.
//
// The `prev == lastWrote` early return keys on this incarnation's OWN persist
// watermark, which is 0 until it writes. A rule that keyed on "the file equals
// what I published" instead would skip exactly the backward-clock-step case
// persistence exists for.
func TestBootEpochRefreshCarriesABackwardClockStep_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	ahead := uint64(time.Now().Add(30 * time.Minute).UnixNano())
	if err := os.WriteFile(path, []byte(strconv.FormatUint(ahead, 10)), 0o644); err != nil {
		t.Fatal(err)
	}
	var published atomic.Uint64
	published.Store(uint64(time.Now().UnixNano()))

	wrote := refineBootEpoch(path, &published, 0)
	if got := published.Load(); got != ahead+1 {
		t.Fatalf("refined epoch = %d, want %d (persisted+1 must dominate a backward clock step)",
			got, ahead+1)
	}
	if wrote != ahead+1 {
		t.Fatalf("returned watermark = %d, want %d — the caller would re-chain from its own "+
			"write on the next pass", wrote, ahead+1)
	}
	// And a second pass with that watermark leaves everything alone.
	if got := refineBootEpoch(path, &published, wrote); got != wrote {
		t.Fatalf("second pass returned watermark %d, want %d", got, wrote)
	}
	if got := published.Load(); got != ahead+1 {
		t.Fatalf("second pass moved the epoch to %d, want %d", got, ahead+1)
	}
}

// parkedRefineWorker starts a refine worker and holds it inside its locked
// pass, returning a func that lets it go. The park is on epochFlock, so the
// worker is stopped where it genuinely can stop for an unbounded time in
// production: inside the file lock, ahead of the read and the fsync.
func parkedRefineWorker(t *testing.T, m *Manager) (release func()) {
	t.Helper()
	atFlock := make(chan struct{})
	releaseWorker := make(chan struct{})
	var once sync.Once
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		once.Do(func() {
			close(atFlock)
			<-releaseWorker
		})
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	m.initHeartbeatEpochState()
	select {
	case <-atFlock:
	case <-time.After(5 * time.Second):
		t.Fatal("the refine worker never reached the file lock")
	}

	var releaseOnce sync.Once
	return func() { releaseOnce.Do(func() { close(releaseWorker) }) }
}

// TestStopJoinsTheBootEpochRefineWorker_6669 pins the half of Manager.Stop that
// did not exist: Stop used to return with a refine worker still in flight.
//
// It needs no race to reach — the worker parks inside a flock or an fsync by
// design, so one sequential shutdown over a wedged store leaves it storing to
// m.bootEpoch and writing the state file on a manager the daemon has finished
// tearing down (and, in tests, outliving the t.Cleanup that restores the
// package vars it reads).
//
// The negative window below is 150 ms against a 2 s join budget: without the
// join Stop returns essentially immediately, so the margin is an order of
// magnitude, not a photo finish.
//
// RED-on-revert: drop the joinBootEpochRefine call at the end of Manager.Stop.
func TestStopJoinsTheBootEpochRefineWorker_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)
	release := parkedRefineWorker(t, m)

	stopped := make(chan struct{})
	go func() {
		m.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned while a boot-epoch refine worker was still in flight; it can " +
			"then still store to m.bootEpoch and write the state file after teardown")
	case <-time.After(150 * time.Millisecond):
	}

	release()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop never returned after the refine worker finished")
	}
	if got := m.bootEpochRefine.Load(); got != 0 {
		t.Fatalf("refine word = %#x after Stop, want 0", got)
	}
}

// TestStopDoesNotBlockOnAWedgedRefineWorker_6669 is the other half, and the one
// that keeps the join from becoming the bug it replaced.
//
// The worker's blocking calls are a flock and an fsync, and this whole
// mechanism exists because those can wedge indefinitely without being allowed
// to stall the HA path — the 2 s wait initHeartbeatEpochState used to take was
// removed for exactly that (measured 2.005/2.012/2.011 s against a 1 s
// dead-peer threshold). Stop runs immediately after VRRP priority-0, so an
// unbounded join here would park a shutdown behind a dead disk.
//
// RED-on-revert: make the join in Manager.Stop unbounded (m.bootEpochWG.Wait())
// and this hangs until the test binary's own timeout.
func TestStopDoesNotBlockOnAWedgedRefineWorker_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	// Count locked passes. Installed BEFORE parkedRefineWorker so that its park
	// hook wraps this one and every pass — parked or not — is counted.
	var passes atomic.Int64
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		passes.Add(1)
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	release := parkedRefineWorker(t, m)

	start := time.Now()
	stopped := make(chan struct{})
	go func() {
		m.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(bootEpochStopJoinBudget + 8*time.Second):
		t.Fatalf("Stop did not return within %v of its %v join budget: the join is not "+
			"bounded, so a wedged store parks the shutdown path",
			8*time.Second, bootEpochStopJoinBudget)
	}
	if elapsed := time.Since(start); elapsed < bootEpochStopJoinBudget {
		t.Fatalf("Stop returned after %v, inside its %v join budget, with the worker still "+
			"wedged — it did not wait for the worker at all", elapsed, bootEpochStopJoinBudget)
	}

	// A stopped manager starts no further refinement: releasing the wedged
	// worker lets it finish its own pass, and the request made afterwards must
	// not spawn another.
	release()
	if !m.joinBootEpochRefine(5 * time.Second) {
		t.Fatal("the wedged refine worker never exited after release")
	}
	passesBefore := passes.Load()
	if passesBefore != 1 {
		t.Fatalf("%d locked pass(es) ran before the stopped-manager probe, want exactly 1; the "+
			"count below is only meaningful against a known baseline", passesBefore)
	}
	wroteBefore := m.bootEpochWrote.Load()
	m.refreshBootEpoch()
	if got := m.bootEpochRefine.Load(); got != 0 {
		t.Fatalf("refine word = %#x after a refresh on a STOPPED manager, want 0 — Stop's "+
			"join is defeated by anything that can still spawn behind it", got)
	}
	// THE TWO ASSERTIONS ABOVE AND BELOW ARE FAILURE DEFAULTS ON THEIR OWN, and
	// an earlier revision of this test stopped at them. A zero word is what an
	// illegal worker that spawned AND finished before this line leaves behind
	// (the claim is taken on the caller's goroutine, but the pass itself is
	// idempotent and short once the store is healthy), and an idempotent pass
	// returns the watermark it was handed, so the watermark does not move
	// either. Both are exactly what a correctly-refused spawn produces. Join,
	// then count the LOCKED PASSES, which nothing but a spawn can move.
	if !m.joinBootEpochRefine(5 * time.Second) {
		t.Fatal("a refine worker was still in flight after a refresh on a STOPPED manager")
	}
	if got := passes.Load(); got != passesBefore {
		t.Fatalf("a stopped manager ran %d further locked refine pass(es) (%d -> %d); Stop's "+
			"join is defeated by anything that can still spawn behind it",
			got-passesBefore, passesBefore, got)
	}
	if got := m.bootEpochWrote.Load(); got != wroteBefore {
		t.Fatalf("a stopped manager still persisted (watermark %d -> %d)", wroteBefore, got)
	}
}

// TestJoinDoesNotBlockBehindAParkedRequester_6669 pins the one thing
// joinBootEpochRefine must never do: wait on bootEpochRefineMu.
//
// Round 14 gave the worker an exit handle and, in its first form, read that
// handle under bootEpochRefineMu. That mutex is held across
// claimBootEpochRefine — and therefore across its epochRefineAfterLostClaim
// seam, where a requester can be parked indefinitely — so the join, the
// worker's own exit defer and the parked requester deadlocked against each
// other in three goroutines. It was NOT caught by any single-test run; it
// surfaced as a ten-minute `panic: test timed out` in
// TestLateRefineRequestCannotBeStranded_6669, which drives exactly this
// schedule for a different purpose. A hang is a bad failure mode: it costs the
// full test timeout and reports no assertion. This test exists to make the same
// defect a two-hundred-millisecond assertion.
//
// The join is bounded BY DESIGN — that is the whole reason it is not
// wg.Wait() — so it must return on its own budget no matter who holds what.
//
// RED-on-revert: read the handle under m.bootEpochRefineMu
// (`m.bootEpochRefineMu.Lock(); w := ...; m.bootEpochRefineMu.Unlock()`) and
// the join below never returns.
func TestJoinDoesNotBlockBehindAParkedRequester_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	// Park the worker at its release seam, so the in-flight bit is still held
	// and the request below must LOSE the claim.
	atRelease := make(chan struct{})
	releaseWorker := make(chan struct{})
	var relOnce sync.Once
	origRelease := epochRefineBeforeRelease
	epochRefineBeforeRelease = func() {
		relOnce.Do(func() {
			close(atRelease)
			<-releaseWorker
		})
	}
	t.Cleanup(func() { epochRefineBeforeRelease = origRelease })

	// Park the requester INSIDE claimBootEpochRefine — which is to say, while it
	// holds bootEpochRefineMu.
	lostClaim := make(chan struct{})
	resumeRequester := make(chan struct{})
	var lostOnce sync.Once
	origLost := epochRefineAfterLostClaim
	epochRefineAfterLostClaim = func() {
		lostOnce.Do(func() {
			close(lostClaim)
			<-resumeRequester
		})
	}
	t.Cleanup(func() { epochRefineAfterLostClaim = origLost })

	// UNPARK ON THE FAILURE PATH TOO, or this test cannot report the very defect
	// it exists for. t.Fatalf runs runtime.Goexit, which skips the explicit
	// unwind at the end of the body but still runs cleanups. Without this, a
	// failing assertion leaves the requester parked holding bootEpochRefineMu,
	// keyedEpochManager's join cleanup blocks on that mutex forever, and the
	// crisp message below is buffered and never printed: the run ends in
	// `panic: test timed out` with no assertion — measured, and exactly the
	// failure mode this test was written to replace.
	//
	// It also JOINS the requester goroutine, and the two must happen in that
	// order on ONE cleanup rather than two: t.Cleanup runs LIFO, so a separately
	// registered join would run BEFORE the unpark and wait on a goroutine
	// nothing had released yet.
	requested := make(chan struct{})
	var unwindOnce sync.Once
	unwind := func() {
		unwindOnce.Do(func() {
			close(resumeRequester)
			close(releaseWorker)
		})
	}
	t.Cleanup(func() {
		unwind()
		// Bounded: if the body failed before starting the requester, nothing
		// ever closes this.
		select {
		case <-requested:
		case <-time.After(5 * time.Second):
		}
	})

	m.initHeartbeatEpochState()
	select {
	case <-atRelease:
	case <-time.After(5 * time.Second):
		t.Fatal("the refine worker never reached its release point")
	}
	// JOIN THIS GOROUTINE, do not just wait for the word. waitBootEpochIdle
	// polls bootEpochRefine, and there is a window where that word reads 0 while
	// this requester is still inside startBootEpochRefine: the worker has
	// released the slot but the unparked requester has not yet re-claimed it. A
	// test that stopped at the word could therefore return and let its cleanups
	// restore bootEpochPath and epochRefineBeforeRelease while this goroutine
	// was still reading them — a flake that reproduced roughly 1 run in 8 at
	// -count=5, and the same "a proxy is not a join" defect awaitFirstRefine
	// exists to stop. keyedEpochManager's join cleanup is no backstop here: it
	// joins a REGISTERED worker, and a requester that has not claimed yet is not
	// one.
	go func() {
		defer close(requested)
		m.refreshBootEpoch()
	}()
	select {
	case <-lostClaim:
	case <-time.After(5 * time.Second):
		t.Fatalf("the requester never reached the lost-claim seam (refine word = %#x)",
			m.bootEpochRefine.Load())
	}

	// bootEpochRefineMu is HELD by the parked requester from here.
	joined := make(chan bool, 1)
	start := time.Now()
	go func() { joined <- m.joinBootEpochRefine(200 * time.Millisecond) }()
	select {
	case ok := <-joined:
		if ok {
			t.Fatal("the join reported a still-parked worker as joined")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("joinBootEpochRefine had not returned %v after its 200ms budget: it is "+
			"waiting on bootEpochRefineMu, which claimBootEpochRefine holds across the "+
			"epochRefineAfterLostClaim seam. The join, the worker's exit and the parked "+
			"requester then deadlock, and a bounded join that can block forever is not "+
			"a bounded join.", time.Since(start))
	}

	// Unwind: let the requester publish its bit, then let the worker serve it.
	unwind()
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("refreshBootEpoch never returned after the unwind")
	}
	waitBootEpochIdle(t, m)
}

// joinWaiterGoroutines counts goroutines parked inside Manager.joinBootEpochRefine
// itself, or in a sync.WaitGroup.Wait reached from this package.
//
// BOTH shapes are counted because the defect is a helper OUTLIVING its caller,
// not the primitive it happens to block on: reverting to a WaitGroup, or moving
// the same `go func() { …; close(done) }()` into a differently-named helper,
// must not slip past this.
func joinWaiterGoroutines() int {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "cluster.(*Manager).joinBootEpochRefine") ||
			(strings.Contains(g, "sync.(*WaitGroup).Wait") && strings.Contains(g, "xpf/pkg/cluster")) {
			n++
		}
	}
	return n
}

// TestTimedOutJoinLeavesNoWaiterBehind_6669 is the fail-on-revert gate for the
// join's OWN resource lifetime, which neither Stop test above touches.
//
// The bound that keeps a shutdown off a dead disk returns the CALLER, and the
// obvious way to write it — spawn `go func() { wg.Wait(); close(done) }()` and
// select it against a timer — returns ONLY the caller. Nothing cancels a
// WaitGroup.Wait, so the helper stays parked for as long as the worker is
// wedged, which over a dead store is for the life of the process.
//
// "Small and bounded" is true of ONE terminal Stop and false across repeated
// calls, and there are several: Stop is public, and waitBootEpochIdle and
// keyedEpochManager join on every epoch test. Measured on the leaking shape:
// eight timed-out joins, eight permanently parked waiters.
//
// RED-on-revert: put a helper back in joinBootEpochRefine — even one that only
// forwards the worker's own channel —
//
//	fwd := make(chan struct{})
//	go func() { <-done; close(fwd) }()
//	select { case <-fwd: return true; case <-timer.C: return false }
//
// and this fails with eight goroutines parked.
func TestTimedOutJoinLeavesNoWaiterBehind_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)
	release := parkedRefineWorker(t, m)
	defer release()

	base := joinWaiterGoroutines()
	const calls = 8
	for i := 0; i < calls; i++ {
		if m.joinBootEpochRefine(5 * time.Millisecond) {
			t.Fatalf("join %d reported a wedged worker as joined", i)
		}
	}
	if leaked := joinWaiterGoroutines() - base; leaked > 0 {
		t.Fatalf("%d goroutine(s) parked in the join after %d timed-out calls, want 0: a helper "+
			"spawned per call is not cancelled by the caller's timeout, so every join over a "+
			"wedged store leaks one for the life of the process", leaked, calls)
	}
}
