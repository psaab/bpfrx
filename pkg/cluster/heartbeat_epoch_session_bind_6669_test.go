package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #6669 fold round 10 — the floor's replacement claim was false FOR EQUAL
// EPOCHS, and two of the recovery claims around it were unconditional when the
// behaviour is not.
//
// The claim was: "sustained ring churn needs heartbeatReplaySessions+1 sessions
// at or above the floor, and one incarnation emits exactly one session, so
// epoch-bearing captures buy only a finite ascending pass." The step that fails
// is DISTINCT SESSIONS => DISTINCT EPOCHS. `epoch == highEpoch` fell through to
// the ring, so any number of sessions sharing ONE valid epoch were all admitted
// AT the floor and churned the ring exactly as epochless frames do.
//
// The measurement that produced the claim could not see it: the corpus in
// heartbeat_epoch_test.go hard-codes strictly increasing epochs (1000+i), so it
// held constant the very variable the defect lives in.
//
// The fix binds the floor to a BOUNDED SET of sessions
// (heartbeatAuthState.highEpochSessions, heartbeatEpochSessionsPerEpoch slots,
// reset by a raise). Round 10 shipped that set as a singleton, which refused a
// legitimate successor incarnation on every heartbeat — see
// TestEqualEpochSuccessorIsAdmitted_6669. These tests pin the closed hole, the
// live-peer path it must not break, and both doors out of a poisoned floor.

// TestEqualEpochsCannotChurnTheRing_6669 is the fail-on-revert gate for the
// equal-epoch replay hole.
//
// RED-on-revert: delete the `epoch == s.highEpoch &&
// !s.epochSessionAdmissible(session)` rejection in admitAuthedLocked (or move
// it AFTER the s.replay.admit call, which is the same ordering bug the floor
// itself has to avoid) and both subtests go back to sustained admits.
func TestEqualEpochsCannotChurnTheRing_6669(t *testing.T) {
	// ALL captures share ONE epoch. This is what a sender with a clock at or
	// before the Unix epoch emits: bootEpochSeed returns the literal 1 for every
	// incarnation, and a store that never completes never raises it.
	t.Run("all_captures_share_one_epoch", func(t *testing.T) {
		e := newEpochEnv(t)
		const n = heartbeatReplaySessions + 1
		const shared = uint64(1_700_000_000_000_000_000)

		caps := make([][][]byte, 0, n)
		for i := 0; i < n; i++ {
			frames := e.captureIncarnation(uint64(0x7000+i), shared, epochFramesPerIncarnation)
			for _, f := range frames {
				e.feed(f)
			}
			caps = append(caps, frames)
		}

		admitted, total := e.replayAll(caps, 5)
		if admitted != 0 {
			t.Fatalf("%d/%d equal-epoch replays admitted, want 0 — %d captured sessions sharing "+
				"one epoch churn the ring exactly as epochless frames do, so the floor buys "+
				"nothing against them", admitted, total, n)
		}
		if got := e.r.auth.peerEpochFloor(); got != shared {
			t.Fatalf("floor = %d, want %d", got, shared)
		}
	})

	// EQUAL MAXIMUM. The sharpest shape: the captures ascend normally — so the
	// ascending pass the claim describes really happens — but the TOP value is
	// shared by heartbeatReplaySessions+1 distinct sessions. Ascending epochs
	// alone (the corpus the original measurement used) cannot reach this.
	t.Run("equal_maximum_epoch_across_many_sessions", func(t *testing.T) {
		e := newEpochEnv(t)
		const ascending = 4
		const atMax = heartbeatReplaySessions + 1
		const base = uint64(1_700_000_000_000_000_000)
		maxEpoch := base + ascending // strictly above every ascending value

		caps := make([][][]byte, 0, ascending+atMax)
		for i := 0; i < ascending; i++ {
			frames := e.captureIncarnation(uint64(0x8000+i), base+uint64(i), epochFramesPerIncarnation)
			e.liveRun(frames, "ascending capture")
			caps = append(caps, frames)
		}
		for i := 0; i < atMax; i++ {
			frames := e.captureIncarnation(uint64(0x9000+i), maxEpoch, epochFramesPerIncarnation)
			for _, f := range frames {
				e.feed(f)
			}
			caps = append(caps, frames)
		}

		admitted, total := e.replayAll(caps, 5)
		if admitted != 0 {
			t.Fatalf("%d/%d replays admitted, want 0 — %d sessions sharing the MAXIMUM epoch "+
				"sustain the churn even though every capture below them is ordered",
				admitted, total, atMax)
		}
		if got := e.r.auth.peerEpochFloor(); got != maxEpoch {
			t.Fatalf("floor = %d, want %d (a replay must never move the floor)", got, maxEpoch)
		}
		if got := e.m.HeartbeatStats().EpochSessionCollision; got == 0 {
			t.Fatal("EpochSessionCollision stayed 0; the operator cannot see the regime that " +
				"produces equal epochs")
		}
	})
}

// TestFloorRebindsToTheRaisingIncarnation_6669 is the negative control, and it
// must pass both WITH and WITHOUT the session binding.
//
// Rejecting at equality is only safe because the LIVE peer keeps its session
// for the life of its incarnation (Manager.heartbeatNonce, #6169 Stage 0) while
// its epoch only ever rises. A guard that rejected every frame at the floor
// would make the test above pass and take the cluster down; this is what
// separates the two.
func TestFloorRebindsToTheRaisingIncarnation_6669(t *testing.T) {
	e := newEpochEnv(t)
	const liveSession = uint64(0xC0FE)
	epoch := uint64(time.Now().Add(-time.Hour).UnixNano())

	// A long run at ONE epoch from ONE session: every frame admitted. This is
	// the ordinary case — a peer emits many heartbeats per second, all carrying
	// the epoch it published at boot.
	for c := 1; c <= 50; c++ {
		if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, uint64(c), epoch)) {
			t.Fatalf("frame %d from the live peer at its OWN bound floor was rejected; the peer "+
				"is declared dead in ~500ms and the cluster goes dual-master", c)
		}
	}
	// Refinement raises the peer's epoch mid-incarnation: the session does not
	// change, and the floor must follow.
	raised := epoch + 1
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 51, raised)) {
		t.Fatal("the live peer's mid-incarnation epoch raise was rejected")
	}
	if got := e.r.auth.peerEpochFloor(); got != raised {
		t.Fatalf("floor = %d after the raise, want %d", got, raised)
	}
	// And it keeps being admitted at the new floor.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 52, raised)) {
		t.Fatal("the live peer was rejected at the floor it had just raised — the binding did " +
			"not follow the raise")
	}
	if got := e.m.HeartbeatStats().EpochSessionCollision; got != 0 {
		t.Fatalf("EpochSessionCollision = %d on a purely legitimate run, want 0", got)
	}
}

// TestPoisonedFloorStillRecoversByRaise_6669 pins BOTH doors out of a poisoned
// floor (#6711), which is the shape the equal-epoch bound changed.
//
// While equality fell through to the ring unconditionally, the only statement
// was "a regressed sender that has climbed back to exactly the floor is
// admitted". Round 10 replaced that with a singleton binding, which shut the
// equality door completely — the archived frame had bound its own session, so
// the live peer at exactly the floor was refused. The bound is now
// heartbeatEpochSessionsPerEpoch rather than one, so BOTH doors are open and
// each has a different shape:
//
//   - AT the floor, while a slot is free. Narrow (one exact value) and finite
//     (the slots do not refill), but it is the door a legitimate successor
//     incarnation that republished its predecessor's epoch comes through.
//   - STRICTLY past the floor. One nanosecond of wall clock rather than an
//     exact value, and never exhausted, so it is the wider of the two.
func TestPoisonedFloorStillRecoversByRaise_6669(t *testing.T) {
	e := newEpochEnv(t)
	const archivedSession, liveSession = uint64(0xAAAA), uint64(0xBBBB)
	floor := uint64(time.Now().Add(-time.Hour).UnixNano())

	// An archived frame from a retired incarnation raises and binds the floor.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, archivedSession, 1, floor)) {
		t.Fatal("the archived frame was refused; the #6711 premise is not reachable")
	}

	// The regressed live peer sits below it — pre-existing #6711, unchanged.
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 1, floor-1000)) {
		t.Fatal("a frame BELOW the floor was admitted")
	}
	// AT it under its own session: admitted, because a slot is free. This is the
	// door a successor incarnation needs, and shutting it is what made a healthy
	// node refused on every heartbeat.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 2, floor)) {
		t.Fatal("the live peer was refused AT the floor with a slot free; a successor " +
			"incarnation that republished its predecessor's epoch is locked out")
	}
	// But the door is FINITE. With the slots spent, a further session at the
	// same value is refused however many times it asks — that is what keeps a
	// shared-epoch capture set from churning the ring.
	for c := 1; c <= 20; c++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xCCCC, uint64(c), floor)) {
			t.Fatalf("frame %d from a third session was admitted at one epoch value; the "+
				"equal-epoch churn is open", c)
		}
	}

	// One nanosecond past: admitted, and the floor rebinds to the live peer.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 3, floor+1)) {
		t.Fatal("the live peer was refused ONE NANOSECOND past the floor — recovery by raise " +
			"is broken, and #6711 becomes unrecoverable rather than merely slow")
	}
	if got := e.r.auth.peerEpochFloor(); got != floor+1 {
		t.Fatalf("floor = %d, want %d", got, floor+1)
	}
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, 4, floor+1)) {
		t.Fatal("the live peer was refused at the floor it had just raised")
	}
}

// TestOverlappingRefineRequestIsCoalesced_6669 is the fail-on-revert gate for
// the dropped recovery request.
//
// startBootEpochRefine used to DROP a refine requested while one was in flight.
// The in-flight worker's locked read can already be complete, so an update that
// lands behind it is invisible to that pass — and the caller who lost the CAS is
// the one asking for the re-read. Dropping it left this node below its peer's
// floor until some later heartbeat start, which nothing bounds (#6724).
//
// The schedule below is that exact shape, driven deterministically through the
// epochFlock seam: pass 1 is held at the lock, a refresh is requested and lost,
// and the update the request exists to pick up lands only AFTER pass 1 has read
// the file — so nothing but a SECOND pass can see it.
//
// RED-on-revert: restore the `if !CAS(false, true) { return }` early return in
// startBootEpochRefine (dropping the bootEpochRefinePending store) and this
// times out waiting for pass 2.
func TestOverlappingRefineRequestIsCoalesced_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	var passes atomic.Int64
	entered := make(chan int, 8)
	releasePass1 := make(chan struct{})
	releasePass2 := make(chan struct{})
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		switch passes.Add(1) {
		case 1:
			entered <- 1
			<-releasePass1
		case 2:
			entered <- 2
			<-releasePass2
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	m.initHeartbeatEpochState()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("pass 1 never reached the lock")
	}

	// The request that must not be lost, made while pass 1 is in flight.
	m.refreshBootEpoch()
	close(releasePass1)

	// Pass 1 runs to completion. Pass 2 must exist at all — that is the fix.
	select {
	case n := <-entered:
		if n != 2 {
			t.Fatalf("expected pass 2, got pass %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d refine pass(es) ran: the overlapping request was DROPPED, so an "+
			"update landing after pass 1's read is never picked up and this node stays "+
			"below its peer's floor", passes.Load())
	}

	// NOW another incarnation raises the file — after pass 1's read, so only
	// pass 2 can carry it. This is what the dropped request cost.
	raised := m.heartbeatBootEpoch() + uint64(time.Hour)
	if err := os.WriteFile(path, []byte(strconv.FormatUint(raised, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	close(releasePass2)
	waitBootEpochIdle(t, m)

	if got := m.heartbeatBootEpoch(); got <= raised {
		t.Fatalf("published epoch = %d, want > %d — the coalesced pass ran but did not chain "+
			"from the value another incarnation left in the file", got, raised)
	}
}

// TestLateRefineRequestIsReclaimed_6669 is the fail-on-revert gate for the
// RE-CLAIM half of the coalescing fix, which nothing else binds.
//
// TestOverlappingRefineRequestIsCoalesced_6669 covers the request that lands
// while the worker is still inside its pass — the worker's own pending check
// sees it and `continue`s. The re-claim below the release covers the OTHER
// window: a request that loses the CAS (so it queues rather than spawning a
// worker) and stores the bit AFTER that check has already run. Nobody else will
// serve it — the setter saw a worker in flight and returned — so without the
// re-claim it is stranded with no worker running, and this node stays below its
// peer's floor until some later heartbeat start that nothing bounds (#6724).
//
// The window is a few instructions wide in production, so hammering does not
// reach it: 3000 rounds x 4 concurrent refreshBootEpoch never landed in it.
// It is driven deterministically through the epochRefineBeforeRelease seam.
//
// RED-on-revert: delete the re-claim step in startBootEpochRefine (everything
// between `m.bootEpochRefining.Store(false)` and the loop's closing brace,
// returning instead) and the second pass never runs.
func TestLateRefineRequestIsReclaimed_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	var passes atomic.Int64
	entered := make(chan int, 8)
	origFlock := epochFlock
	epochFlock = func(fd int, how int) error {
		if n := passes.Add(1); n >= 2 {
			entered <- int(n)
		}
		return origFlock(fd, how)
	}
	t.Cleanup(func() { epochFlock = origFlock })

	atRelease := make(chan struct{})
	releaseWorker := make(chan struct{})
	var once sync.Once
	origHook := epochRefineBeforeRelease
	epochRefineBeforeRelease = func() {
		once.Do(func() {
			close(atRelease)
			<-releaseWorker
		})
	}
	t.Cleanup(func() { epochRefineBeforeRelease = origHook })

	m.initHeartbeatEpochState()
	select {
	case <-atRelease:
	case <-time.After(5 * time.Second):
		t.Fatal("the refine worker never reached its release point")
	}

	// Pass 1 is COMPLETE (it has read, written and checked pending) but the
	// in-flight flag is still held, so this request loses the CAS and queues —
	// too late for the check that just ran.
	if !m.bootEpochRefining.Load() {
		t.Fatal("the worker released the in-flight flag before the seam; the window this " +
			"test drives is not the one the re-claim covers")
	}
	m.refreshBootEpoch()
	if !m.bootEpochRefinePending.Load() {
		t.Fatal("the request did not queue: it either spawned a second worker or was dropped")
	}

	// Another incarnation raises the file. Pass 1 has already read AND written,
	// so only a second pass can carry it — which is exactly what the queued
	// request is for.
	raised := m.heartbeatBootEpoch() + uint64(time.Hour)
	if err := os.WriteFile(path, []byte(strconv.FormatUint(raised, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	close(releaseWorker)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("only %d refine pass(es) ran: a request that queued AFTER the worker's own "+
			"pending check was STRANDED with no worker to serve it", passes.Load())
	}
	waitBootEpochIdle(t, m)

	if got := m.heartbeatBootEpoch(); got <= raised {
		t.Fatalf("published epoch = %d, want > %d — the re-claimed pass ran but did not chain "+
			"from the value another incarnation left in the file", got, raised)
	}
}

// TestCoalescingDoesNotRatchetOnAHealthyNode_6669 is the negative control for
// the coalescing loop: the extra pass must still be idempotent.
//
// A worker that re-ran unconditionally would ratchet the epoch by one on every
// heartbeat start, which is exactly what refineBootEpoch's `prev == lastWrote`
// shortcut exists to prevent. Coalescing adds passes, so it is the change most
// able to break that.
func TestCoalescingDoesNotRatchetOnAHealthyNode_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	m := keyedEpochManager(t, path)

	m.initHeartbeatEpochState()
	select {
	case <-m.bootEpochReady:
	case <-time.After(5 * time.Second):
		t.Fatal("the first refine never completed")
	}
	first := m.heartbeatBootEpoch()
	firstFile := readPersistedEpoch(t, path)

	// Pile requests on: several land while a worker is in flight and coalesce.
	for i := 0; i < 20; i++ {
		m.refreshBootEpoch()
	}
	waitBootEpochIdle(t, m)

	if got := m.heartbeatBootEpoch(); got != first {
		t.Fatalf("published epoch moved from %d to %d under coalesced refreshes; a healthy "+
			"node must not ratchet", first, got)
	}
	if got := readPersistedEpoch(t, path); got != firstFile {
		t.Fatalf("state file moved from %d to %d under coalesced refreshes", firstFile, got)
	}
}

// TestPostRenameSyncKeepsTheWatermark_6669 is the fail-on-revert gate for the
// durability-error misclassification.
//
// refineBootEpoch assumed every WriteFileDurable error meant the file had not
// moved. fsatomic documents otherwise: a *PostRenameSyncError is a
// directory-fsync failure AFTER a successful rename, so the new content is
// VISIBLE (#5185) and only its durability is unknown. Returning the old
// watermark there made the next pass fail to recognise its own value, chain
// from it, and rewrite epoch+1 — ratcheting on EVERY pass for as long as the
// fsync kept failing.
//
// RED-on-revert: delete the errors.As(*fsatomic.PostRenameSyncError) branch in
// refineBootEpoch and the file climbs by one per pass here.
func TestPostRenameSyncKeepsTheWatermark_6669(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	restore := fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
		return errors.New("injected post-rename directory fsync failure")
	})
	t.Cleanup(restore)

	var published atomic.Uint64
	published.Store(uint64(time.Now().UnixNano()))

	var wrote uint64
	const passes = 5
	seen := make([]uint64, 0, passes)
	for i := 0; i < passes; i++ {
		wrote = refineBootEpoch(path, &published, wrote)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("pass %d: the post-rename content must be VISIBLE, so the file must "+
				"exist: %v", i, err)
		}
		n, perr := strconv.ParseUint(string(data[:len(data)-1]), 10, 64)
		if perr != nil {
			t.Fatalf("pass %d: parse %q: %v", i, data, perr)
		}
		seen = append(seen, n)
	}

	for i, got := range seen {
		if got != seen[0] {
			t.Fatalf("pass %d left %d in the file, want %d — a post-rename fsync failure is "+
				"being read as 'nothing was written', so every pass chains from its own "+
				"value and ratchets (%v)", i, got, seen[0], seen)
		}
	}
	if wrote != seen[0] {
		t.Fatalf("watermark = %d, want %d: the pass DID move the file and must say so", wrote, seen[0])
	}
	if got := published.Load(); got != seen[0] {
		t.Fatalf("published = %d, want %d", got, seen[0])
	}
}

// TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669 is a CHARACTERIZATION,
// not a fix. It states the two conditions the re-runnable-refinement recovery
// claim actually carries, both of which were left unsaid.
//
// Manager.refreshBootEpoch bounds "an incarnation stranded below its peer's
// floor is pinned there for the life of the process". It does so by re-reading
// the FILE, so it recovers only what the file can express.
//
// CONDITION 1 — the floor-raising epoch must have REACHED the file. Refinement
// publishes the raised value before persisting it, deliberately: a node that
// read a predecessor's higher value must still order itself above it even when
// it cannot write (that is the backward-clock-step case persistence exists
// for). The cost is that A can EMIT `b+1` while the file still reads `b`. B
// then has no signal at all — it wrote `b`, the file says `b` — so every
// restart returns at the `prev == lastWrote` shortcut and B stays below the
// peer's floor for its process lifetime. No amount of restarting helps, because
// the information is not in the only channel B reads.
//
// CONDITION 2 — A must be GONE. While both run, each pass raises above the
// other and the file ratchets, so they leapfrog and alternately strand each
// other. TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669 shows the
// recovery working; it makes A exit first, and that is load-bearing.
//
// Closing either needs state this design does not keep — a writer identity in
// the file, or a lifetime-held liveness lock. Both are larger changes than the
// epoch itself; see withEpochFileLock. Tracked as #6724.
func TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669(t *testing.T) {
	t.Run("a_failed_write_strands_the_peer_across_every_restart", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ha-boot-epoch")
		mB := keyedEpochManager(t, path)

		mB.initHeartbeatEpochState()
		select {
		case <-mB.bootEpochReady:
		case <-time.After(5 * time.Second):
			t.Fatal("B's first refine never completed")
		}
		b := mB.heartbeatBootEpoch()
		if got := readPersistedEpoch(t, path); got != b {
			t.Fatalf("persisted %d after B's refine, want %d", got, b)
		}

		// A is older and delayed. Its write FAILS — but it has already read `b`,
		// so it raises and emits `b+1` regardless.
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		var pubA atomic.Uint64
		pubA.Store(b - uint64(time.Second))
		refineBootEpoch(path, &pubA, 0)
		epochA := pubA.Load()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if epochA <= b {
			t.Fatalf("A published %d, which does not exceed B's %d — the schedule this test "+
				"describes did not happen, so the assertions below prove nothing", epochA, b)
		}
		if got := readPersistedEpoch(t, path); got != b {
			t.Fatalf("the file holds %d, want B's %d — A's write was supposed to FAIL, so this "+
				"subtest is exercising the wrong path", got, b)
		}

		// The peer latches A's value and refuses B.
		var peer heartbeatAuthState
		if !peer.admitAuthed(true, epochA, 0xA669, 1) {
			t.Fatal("the peer refused A")
		}
		if peer.admitAuthed(true, b, 0xB669, 1) {
			t.Fatal("the peer admitted B; the mis-ordering premise is not reachable")
		}

		// A exits. B restarts refinement repeatedly and STAYS STRANDED — the
		// documented recovery does not apply, because the value that raised the
		// floor is not in the file.
		for i := 0; i < 5; i++ {
			mB.initHeartbeatEpochState()
			waitBootEpochIdle(t, mB)
		}
		if got := mB.heartbeatBootEpoch(); got > epochA {
			t.Fatalf("B recovered to %d, above A's %d. If that is now genuinely reachable the "+
				"recovery claim can be stated unconditionally and this characterization "+
				"should be replaced by a fix-gate.", got, epochA)
		}
		if peer.admitAuthed(true, mB.heartbeatBootEpoch(), 0xB66A, 2) {
			t.Fatal("the peer admitted B after all; see above")
		}
	})

	t.Run("two_live_incarnations_leapfrog_and_ratchet_the_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		now := uint64(time.Now().UnixNano())
		var pubA, pubB atomic.Uint64
		pubA.Store(now - uint64(time.Second))
		pubB.Store(now)

		var wroteA, wroteB uint64
		wroteB = refineBootEpoch(path, &pubB, wroteB)
		start := readPersistedEpoch(t, path)

		const rounds = 4
		for i := 0; i < rounds; i++ {
			wroteA = refineBootEpoch(path, &pubA, wroteA)
			if pubA.Load() <= pubB.Load() {
				t.Fatalf("round %d: A at %d did not overtake B at %d", i, pubA.Load(), pubB.Load())
			}
			wroteB = refineBootEpoch(path, &pubB, wroteB)
			if pubB.Load() <= pubA.Load() {
				t.Fatalf("round %d: B at %d did not overtake A at %d", i, pubB.Load(), pubA.Load())
			}
		}

		end := readPersistedEpoch(t, path)
		if end <= start {
			t.Fatalf("the file did not ratchet (%d -> %d); the leapfrog this documents is not "+
				"reachable and the condition can be dropped from the recovery claim", start, end)
		}
	})
}
