package cluster

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6169 — the DOWNGRADE LATCH.
//
// The boot-epoch floor only ever sees frames that CARRY an epoch. An attacker's
// captured incarnations are, by construction, mostly from BEFORE the upgrade
// and therefore carry none, so a receiver that accepts epochless frames forever
// never consults the floor at all. Measured on the first cut of this change,
// with the floor latched at a live peer's epoch: 975/975 epochless replays
// admitted.
//
// The latch closes that: once the peer has proved it emits epochs, an epochless
// frame from it is refused. It is restored from the DURABLE floor at start,
// because an in-memory latch is cleared by exactly the receiver restart an
// attacker waits for.

// latchEnv is an epochEnv plus the ability to model a FULL receiver daemon
// restart (a brand-new Manager, so every in-memory tracker is gone).
type latchEnv struct {
	*epochEnv
}

func newLatchEnv(t *testing.T) *latchEnv {
	t.Helper()
	return &latchEnv{epochEnv: newEpochEnv(t)}
}

// restartDaemon models a FULL receiver daemon restart. Unlike a heartbeat
// restart or a VRF rebind — which preserve Manager.hbAuth (#5086/#6642) — this
// discards every in-memory tracker, including the downgrade latch.
func (e *latchEnv) restartDaemon() {
	e.m = NewManager(0, 42)
	e.r = newHeartbeatReceiver(e.m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
}

// epochlessCaptures builds n distinct PRE-UPGRADE (epochless) incarnations —
// what an on-link sniffer holds from before the cluster was upgraded.
func (e *latchEnv) epochlessCaptures(n int) [][][]byte {
	caps := make([][][]byte, 0, n)
	for i := 0; i < n; i++ {
		caps = append(caps, e.captureIncarnation(uint64(0x9000+i), 0, epochFramesPerIncarnation))
	}
	return caps
}

// TestHeartbeatEpochlessReplayRefusedOnceLatched_6169 is the fail-on-revert
// gate for the finding that the epoch floor alone closes almost nothing.
//
// RED-on-revert: the fix is the `if s.epochSeen { return false }` branch in
// heartbeatAuthState.admitAuthedLocked. Delete it and the epochless replays are
// admitted again (975/975 on the pre-fix code), because they never reach the
// floor comparison at all.
func TestHeartbeatEpochlessReplayRefusedOnceLatched_6169(t *testing.T) {
	e := newLatchEnv(t)

	// The live peer is upgraded: it signs a boot epoch, and the receiver both
	// latches and records a floor from real traffic.
	live := e.captureIncarnation(0x11E0, 9_000_000_000_000_000, epochFramesPerIncarnation)
	e.liveRun(live, "live upgraded incarnation")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("an accepted epoch-bearing frame must arm the downgrade latch")
	}

	// The attacker replays a ringful-and-then-some of PRE-UPGRADE, epochless
	// captures — more than heartbeatReplaySessions, so the FIFO ring alone is
	// churnable and would admit every one of them.
	caps := e.epochlessCaptures(heartbeatReplaySessions + 8)
	admitted, total := e.replayAll(caps, 3)
	if admitted != 0 {
		t.Fatalf("epochless replay: %d/%d admitted, want 0 — a pre-upgrade capture set "+
			"still bypasses the boot-epoch floor entirely", admitted, total)
	}

	// NEGATIVE CONTROL (passes with and without the latch): the live peer keeps
	// working, and a genuine reboot into a higher epoch is still admitted.
	next := marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x11E0,
		uint64(len(live)+1), 9_000_000_000_000_000)
	if !e.feed(next) {
		t.Fatal("the live peer's next genuine frame was rejected")
	}
	rebooted := e.captureIncarnation(0x11E1, 9_000_000_000_000_001, epochFramesPerIncarnation)
	e.liveRun(rebooted, "genuine peer reboot")
}

// TestHeartbeatEpochLatchScopeIsTheProcess_6169 pins the ACTUAL durability
// contract, in both directions, so the boundary is deliberate rather than
// discovered.
//
// The latch survives the restarts that happen routinely — a heartbeat restart,
// a DHCP-triggered VRF rebind, an HA comms restart — because the state lives on
// Manager.hbAuth (#5086/#6642). It does NOT survive a full daemon restart, and
// a live peer re-arms it with its next heartbeat.
//
// An earlier revision persisted the floor to disk to cover the daemon-restart
// case too. Review priced that: it made a deliberate rollback require deleting
// a state file, opened a crash window between accepting a frame and committing
// the floor, needed cross-process locking, and let an in-range-but-wrong epoch
// lock a peer out across reboots. The narrow window it closed is covered
// operationally by PSK rotation.
func TestHeartbeatEpochLatchScopeIsTheProcess_6169(t *testing.T) {
	e := newLatchEnv(t)
	const liveEpoch = uint64(9_100_000_000_000_000)
	e.liveRun(e.captureIncarnation(0x22E0, liveEpoch, epochFramesPerIncarnation), "live upgraded incarnation")

	// A ROUTINE heartbeat restart (VRF rebind / comms restart) must NOT clear
	// the latch or the floor — this is the case that matters day to day.
	e.restartHeartbeat()
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("a heartbeat restart must not clear the downgrade latch (#5086/#6642 anchoring)")
	}
	if got := e.r.auth.peerEpochFloor(); got != liveEpoch {
		t.Fatalf("floor after a heartbeat restart = %d, want %d", got, liveEpoch)
	}
	admitted, total := e.replayAll(e.epochlessCaptures(heartbeatReplaySessions+8), 3)
	if admitted != 0 {
		t.Fatalf("epochless replay after a heartbeat restart: %d/%d admitted, want 0", admitted, total)
	}

	// A FULL daemon restart clears it. Documented, and the reason rollback
	// recovery is "restart xpfd" rather than deleting a state file.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a full daemon restart is documented to clear the latch; it did not")
	}

	// And the live peer re-arms it on its very next heartbeat — one interval.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x22E1, 1, liveEpoch+1)) {
		t.Fatal("the live peer's first post-restart frame must be accepted")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("one genuine epoch-bearing heartbeat must re-arm the latch")
	}
	admitted, total = e.replayAll(e.epochlessCaptures(heartbeatReplaySessions+8), 3)
	if admitted != 0 {
		t.Fatalf("epochless replay after re-arming: %d/%d admitted, want 0", admitted, total)
	}
	// The floor came back with it, so retired incarnations stay rejected.
	for i, f := range e.captureIncarnation(0x22DF, liveEpoch-1, epochFramesPerIncarnation) {
		if e.feed(f) {
			t.Fatalf("retired-epoch frame %d admitted after re-arming", i)
		}
	}
}

// TestHeartbeatEpochUpgradeWindowStillAccepts_6169 is the migration gate. The
// latch must be armed by OBSERVATION, never by local build version: until the
// peer has proved it emits epochs, its epochless frames must be accepted or a
// rolling upgrade splits the cluster — which is worse than the replay this
// closes. This must pass in every world.
func TestHeartbeatEpochUpgradeWindowStillAccepts_6169(t *testing.T) {
	e := newLatchEnv(t)

	if e.r.auth.peerEpochLatched() {
		t.Fatal("a receiver that has never seen an epoch must not be latched")
	}
	// The peer is still on a pre-#6169 build for a good while.
	for i := 0; i < 5; i++ {
		frames := e.captureIncarnation(uint64(0x3300+i), 0, epochFramesPerIncarnation)
		e.liveRun(frames, "not-yet-upgraded peer")
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("epochless traffic must never arm the latch")
	}
	// The peer is upgraded mid-flight and starts signing epochs. Accepted, and
	// only now does the latch arm.
	e.liveRun(e.captureIncarnation(0x33FF, 9_200_000_000_000_000, epochFramesPerIncarnation), "peer after upgrade")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the latch must arm once the peer proves it emits epochs")
	}
}

// TestHeartbeatEpochRollbackRefusedThenRecovered_6169 states, in executable
// form, exactly what happens when a peer is rolled back to a pre-#6169 build —
// the one legitimate trigger the latch cannot distinguish from an attack.
//
// The peer IS refused; that is the deliberate trade, and the same one #4107's
// sticky peerAuthSeen already makes for the auth trailer. Recovery is
// `systemctl restart xpfd` on the refusing node — an operation operators
// already perform, with no state file to hand-edit. That is the reason the
// latch is process-scoped: an earlier revision persisted it, which turned this
// procedure into "delete the right file on the right node, then restart".
func TestHeartbeatEpochRollbackRefusedThenRecovered_6169(t *testing.T) {
	e := newLatchEnv(t)
	e.liveRun(e.captureIncarnation(0x44E0, 9_300_000_000_000_000, epochFramesPerIncarnation), "peer on an epoch-capable build")

	// Operator rolls the peer back: fresh session, fresh counter, no epoch.
	// Refused — indistinguishable on the wire from a replayed capture.
	rolledBack := e.captureIncarnation(0x44FF, 0, epochFramesPerIncarnation)
	for i, f := range rolledBack {
		if e.feed(f) {
			t.Fatalf("rolled-back peer frame %d was admitted — the latch is not engaging", i)
		}
	}
	if got := e.m.HeartbeatStats().EpochDowngradeRejected; got != uint64(len(rolledBack)) {
		t.Fatalf("EpochDowngradeRejected = %d, want %d — the operator must be able to SEE the refusal",
			got, len(rolledBack))
	}

	// Documented recovery: restart xpfd on the refusing node. No file to delete.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a daemon restart must disarm the latch")
	}
	e.liveRun(rolledBack, "rolled-back peer after restarting xpfd on the refusing node")
}

// TestHeartbeatEpochImplausibleValueCannotLockOut_6169 pins the one-way-door
// guard. An epoch outside the plausibility band must never become the floor —
// latching, say, MaxUint64 would reject every subsequent genuine frame forever.
// It still satisfies the latch, because the peer demonstrably emits epochs.
func TestHeartbeatEpochImplausibleValueCannotLockOut_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A frame carrying an epoch the floor cannot ORDER is REFUSED, not
	// admitted-and-ignored: a frame outside the comparable range would be
	// governed by the bounded ring alone, which is the epochless bypass in
	// miniature.
	for _, bad := range []uint64{
		math.MaxUint64,
		epochPlausibleMax,
		uint64(time.Now().UnixNano()) + bootEpochMaxSkew*2, // plausible year, but far ahead of us
	} {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x55E0, 1, bad)) {
			t.Fatalf("a frame with an unorderable epoch (%d) was admitted", bad)
		}
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d, want 0 — an unorderable epoch must never be latched as the floor", got)
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a REFUSED frame must not arm the latch")
	}
	// The genuine peer with an ordinary epoch is still accepted the moment it
	// comes back into range — the refusal must not be a one-way door.
	e.liveRun(e.captureIncarnation(0x55E1, 9_400_000_000_000_000, epochFramesPerIncarnation), "genuine peer after an unorderable epoch")
}

// TestHeartbeatEpochlessAdmitsAreCounted_6169 pins the OBSERVABILITY guard.
//
// Until the peer has proved it emits epochs, an epochless frame is admitted on
// the bounded ring alone — which is the mechanism that stops working past
// heartbeatReplaySessions captures. That residual must be VISIBLE: an operator
// who has upgraded both nodes otherwise has no way to tell whether the cluster
// is still accepting pre-upgrade-shaped frames, and the documentation would be
// the only defence.
//
// The guard asserts the COUNT, not merely that the code path exists.
func TestHeartbeatEpochlessAdmitsAreCounted_6169(t *testing.T) {
	e := newLatchEnv(t)

	if got := e.r.auth.epochlessAdmitted.Load(); got != 0 {
		t.Fatalf("epochlessAdmitted starts at %d, want 0", got)
	}
	// A not-yet-upgraded peer: every admitted frame must be counted.
	const n = 7
	e.liveRun(e.captureIncarnation(0x88E0, 0, n), "not-yet-upgraded peer")
	if got := e.r.auth.epochlessAdmitted.Load(); got != n {
		t.Fatalf("epochlessAdmitted = %d after %d admitted epochless frames, want %d", got, n, n)
	}

	// An epoch-bearing frame must NOT be counted as epochless exposure.
	e.liveRun(e.captureIncarnation(0x88E1, 9_600_000_000_000_000, 3), "upgraded peer")
	if got := e.r.auth.epochlessAdmitted.Load(); got != n {
		t.Fatalf("epochlessAdmitted = %d after epoch-bearing frames, want it unchanged at %d", got, n)
	}

	// Once latched, epochless frames are REFUSED — counted separately, and the
	// exposure meter must not climb.
	before := e.r.auth.epochDowngradeRejected.Load()
	const rejects = 4
	for i := 0; i < rejects; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, uint64(0x88F0+i), 1, 0)) {
			t.Fatal("epochless frame admitted after the latch armed")
		}
	}
	if got := e.r.auth.epochDowngradeRejected.Load(); got != before+rejects {
		t.Fatalf("epochDowngradeRejected = %d, want %d", got, before+rejects)
	}
	if got := e.r.auth.epochlessAdmitted.Load(); got != n {
		t.Fatalf("epochlessAdmitted climbed to %d on REFUSED frames, want %d", got, n)
	}

	// And it reaches the operator surface.
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
	st := e.m.HeartbeatStats()
	if st.EpochlessAdmitted != n {
		t.Fatalf("HeartbeatStats.EpochlessAdmitted = %d, want %d", st.EpochlessAdmitted, n)
	}
	if st.EpochDowngradeRejected != before+rejects {
		t.Fatalf("HeartbeatStats.EpochDowngradeRejected = %d, want %d", st.EpochDowngradeRejected, before+rejects)
	}
}

// TestHeartbeatEpochLatchLayersOverPeerAuthSeen_6169 states how the #6169 epoch
// latch composes with the #4107 peerAuthSeen latch. They are LAYERED, not
// duplicative, and neither subsumes the other:
//
//   - peerAuthSeen latches "the peer proved it holds the PSK" and refuses
//     UNSIGNED frames from then on.
//   - epochSeen latches "the peer proved it runs an epoch-capable build" and
//     refuses SIGNED-BUT-EPOCHLESS frames from then on.
//
// An attacker's replayed pre-upgrade capture is genuinely signed (it was
// captured off a keyed cluster), so it passes the first gate and is stopped only
// by the second — which is exactly why the epoch latch was needed. An unsigned
// frame never reaches the epoch gate at all: readLoop only calls admitAuthed
// when the MAC verified.
//
// The remaining open path is a cluster with NO key configured, where neither
// mechanism exists because there is no MAC to verify and the epoch marker is
// key-derived. That is #6624's domain — an unkeyed chassis cluster is refused at
// commit — and is out of scope here.
func TestHeartbeatEpochLatchLayersOverPeerAuthSeen_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A signed, epoch-bearing frame arms BOTH latches.
	e.liveRun(e.captureIncarnation(0x99E0, 9_700_000_000_000_000, 3), "signed peer with an epoch")
	if !e.r.auth.peerAuthenticated() {
		t.Fatal("#4107: an accepted signed frame must arm peerAuthSeen")
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("#6169: an accepted epoch-bearing frame must arm epochSeen")
	}

	// UNSIGNED frame -> stopped by the #4107 gate, before admitAuthed runs.
	unsigned := MarshalHeartbeat(samplePkt())
	if _, _, present := heartbeatAuthTrailer(unsigned); present {
		t.Fatal("test frame unexpectedly carries an auth trailer")
	}
	if e.feed(unsigned) {
		t.Fatal("#4107: an unsigned frame must be refused once the peer has authenticated")
	}

	// SIGNED but epochless -> passes #4107 (the MAC verifies), stopped by #6169.
	signedEpochless := MarshalHeartbeatAuth(samplePkt(), e.key, 0x99E1, 1)
	if !verifyHeartbeatMAC(signedEpochless, e.key) {
		t.Fatal("test frame should verify")
	}
	if e.feed(signedEpochless) {
		t.Fatal("#6169: a signed but epochless frame must be refused once the epoch latch armed")
	}
}

// TestHeartbeatUnorderableEpochNeverArmsLatch_6169 makes the corrected
// admitAuthed comment executable.
//
// An earlier revision of this change ADMITTED an unorderable epoch without
// latching it; the comment above admitAuthed still described that behaviour
// after the code changed to REFUSE. Both halves are pinned here so the comment
// cannot drift from the code again:
//
//   - a frame whose epoch cannot be ordered is refused and does NOT arm the
//     latch, and
//   - the second-order consequence is the SAFE direction — because the latch
//     never armed, a peer that is later rolled back to a pre-#6169 build is
//     still accepted. Refusing an unorderable epoch never strands a peer.
func TestHeartbeatUnorderableEpochNeverArmsLatch_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A peer whose clock runs years ahead: refused outright.
	farAhead := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
	for i := 0; i < 5; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xCC01, uint64(i+1), farAhead)) {
			t.Fatalf("frame %d with a far-future epoch was admitted", i)
		}
	}
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a refused frame must never arm the downgrade latch")
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d, want 0", got)
	}
	// A restart does not inherit a bogus latch either.
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("a refused frame must not leave a latch behind")
	}

	// The safe direction: that peer, rolled back to a pre-#6169 build, is still
	// accepted — the latch never armed on it.
	e.liveRun(e.captureIncarnation(0xCC02, 0, epochFramesPerIncarnation), "peer rolled back after a far-future epoch")
}

// TestHeldFlockCannotCauseFalsePeerDeath_6169 reproduces, link by link, the
// exact chain a tie-break review measured against an earlier revision of this
// change:
//
//	held the real flock            -> StartHeartbeat returned after 2.0076s, bootEpoch 0
//	bootEpoch 0 => epochless frame -> heartbeatFrameEpoch: present=false
//	latched peer rejects them      -> fresh-nonce valid-MAC frames ALL rejected
//	rejection => declared dead     -> PeerAlive() false after 500ms
//
// A local, recoverable storage stall became a peer-declared death in 500ms — an
// availability regression on exactly the path this change exists to protect,
// and caused by the change itself.
//
// The chain is broken at LINK 1: the boot epoch is published synchronously from
// the wall clock before any file is touched, so a held lock (or a hung fsync,
// or an unwritable state dir) cannot make this node emit an epochless frame.
// The remaining links are asserted anyway, because the property that matters is
// the end of the chain, not the beginning.
//
// RED-on-revert: gate publication on the worker again (store bootEpoch only
// after refineBootEpoch) and link 1 fails immediately.
func TestHeldFlockCannotCauseFalsePeerDeath_6169(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	// Hold the REAL advisory lock the persist path takes, for the whole test.
	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("could not take the lock the test needs to hold: %v", err)
	}

	// LINK 1 — the sender still has an epoch, immediately, with the lock held.
	sender := NewManager(0, 42)
	start := time.Now()
	epoch := sender.heartbeatBootEpoch()
	elapsed := time.Since(start)
	if epoch == 0 {
		t.Fatal("LINK 1: bootEpoch is 0 while the persist lock is held — a storage stall " +
			"makes this node emit epochless frames, which a latched peer rejects")
	}
	if elapsed > time.Second {
		t.Fatalf("LINK 1: heartbeatBootEpoch blocked for %v on a held lock; it must not do I/O", elapsed)
	}

	// LINK 2 — the frames it emits carry that epoch.
	key := []byte("cluster-shared-secret")
	frame := marshalHeartbeatAuthEpoch(samplePkt(), key, 0xDD01, 1, epoch)
	got, present := heartbeatFrameEpoch(frame, key)
	if !present || got != epoch {
		t.Fatalf("LINK 2: frame epoch = (%d,%v), want (%d,true)", got, present, epoch)
	}

	// LINK 3 — a LATCHED peer accepts them.
	e := newLatchEnv(t)
	e.liveRun(e.captureIncarnation(0xDD00, epoch-1000, epochFramesPerIncarnation), "arming the peer's latch")
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("test setup: the receiver should be latched")
	}
	for c := 1; c <= 5; c++ {
		f := marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xDD01, uint64(c), epoch)
		if !e.feed(f) {
			t.Fatalf("LINK 3: a latched peer REJECTED frame %d from a node whose storage is stalled", c)
		}
	}

	// LINK 4 — and therefore never declares it dead.
	e.r.checkTimeout()
	if !e.m.PeerAlive() {
		t.Fatal("LINK 4: peer declared DEAD while its heartbeats were being accepted")
	}

	// The lock is still held, so nothing above depended on the persist landing.
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the epoch was persisted despite the lock being held; the lock is not exclusive")
	}

	// Release and drain the worker before the test ends, so its write cannot
	// race t.TempDir() cleanup. This also demonstrates the self-heal the
	// tie-break observed: the persist completes once the lock frees.
	_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	select {
	case <-sender.bootEpochReady:
	case <-time.After(5 * time.Second):
		t.Fatal("the persist worker never completed after the lock was released")
	}
	if sender.heartbeatBootEpoch() == 0 {
		t.Fatal("the epoch went back to 0 after the persist completed")
	}
}
