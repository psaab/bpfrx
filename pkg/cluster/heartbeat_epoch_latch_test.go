package cluster

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
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

// latchEnv is an epochEnv wired to a temp-dir durable floor, so the tests can
// model a receiver daemon restart.
type latchEnv struct {
	*epochEnv
	floorPath string
	store     *peerEpochFloorStore
}

func newLatchEnv(t *testing.T) *latchEnv {
	t.Helper()
	e := &latchEnv{
		epochEnv:  newEpochEnv(t),
		floorPath: filepath.Join(t.TempDir(), "ha-peer-epoch-floor"),
	}
	e.primeFromDisk()
	return e
}

// primeFromDisk models what StartHeartbeat does via initHeartbeatEpochState:
// load the durable floor and install the persist hook before any frame is
// admitted. Writes are synchronous here so the tests are deterministic; in
// production the hook hands off to a goroutine.
func (e *latchEnv) primeFromDisk() {
	e.store = &peerEpochFloorStore{path: e.floorPath}
	floor := e.store.load()
	store := e.store
	e.r.auth.primeEpochFloor(floor, func(epoch uint64) { store.store(epoch) })
}

// restartDaemon models a FULL receiver daemon restart: a brand-new Manager and
// receiver (so all in-memory anti-replay state is gone), re-primed from the
// same durable floor file.
func (e *latchEnv) restartDaemon() {
	e.m = NewManager(0, 42)
	e.r = newHeartbeatReceiver(e.m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
	e.primeFromDisk()
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

// TestHeartbeatEpochLatchSurvivesDaemonRestart_6169 pins the DURABILITY half.
// An in-memory latch is cleared by a receiver daemon restart, which is exactly
// the moment an attacker replays: the restarted node comes up with an empty
// ring AND an unarmed latch, and the whole captured run is re-admitted.
//
// RED-on-revert: make peerEpochFloorStore.store a no-op (or load return 0) and
// the post-restart replay is admitted again.
func TestHeartbeatEpochLatchSurvivesDaemonRestart_6169(t *testing.T) {
	e := newLatchEnv(t)

	const liveEpoch = uint64(9_100_000_000_000_000)
	e.liveRun(e.captureIncarnation(0x22E0, liveEpoch, epochFramesPerIncarnation), "live upgraded incarnation")

	// The floor reached stable storage. Reported non-fatally so that when this
	// regresses the test still runs on to the SECURITY assertion below — the
	// red should show replays being admitted, not just a missing file.
	if raw, err := os.ReadFile(e.floorPath); err != nil {
		t.Errorf("floor not persisted: %v", err)
	} else if got, _ := strconv.ParseUint(string(raw[:len(raw)-1]), 10, 64); got != liveEpoch {
		t.Errorf("persisted floor = %s, want %d", raw, liveEpoch)
	}

	// The peer dies and the SURVIVOR's daemon restarts — every in-memory
	// tracker is gone.
	e.restartDaemon()
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("the durable floor must re-arm the downgrade latch across a daemon restart")
	}
	if got := e.r.auth.peerEpochFloor(); got != liveEpoch {
		t.Fatalf("restored floor = %d, want %d", got, liveEpoch)
	}

	// Pre-upgrade epochless captures: still refused.
	admitted, total := e.replayAll(e.epochlessCaptures(heartbeatReplaySessions+8), 3)
	if admitted != 0 {
		t.Fatalf("post-restart epochless replay: %d/%d admitted, want 0", admitted, total)
	}
	// And a RETIRED epoch-bearing incarnation is still below the restored floor.
	retired := e.captureIncarnation(0x22DF, liveEpoch-1, epochFramesPerIncarnation)
	for i, f := range retired {
		if e.feed(f) {
			t.Fatalf("retired-epoch frame %d admitted after a daemon restart", i)
		}
	}
	// NEGATIVE CONTROL: the genuine peer, rebooted into a higher epoch, is
	// still admitted after the restart — the durable floor must not wedge a
	// live cluster.
	e.liveRun(e.captureIncarnation(0x22E1, liveEpoch+1, epochFramesPerIncarnation), "genuine peer reboot after restart")
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
// The peer IS refused. That is the deliberate trade, and it is the same one
// #4107's sticky peerAuthSeen already makes for the auth trailer, made durable.
// Recovery is an explicit operator act: clear the persisted floor and restart,
// which is what the rate-limited rejection log instructs
// (Manager.NoteEpochDowngradeHeartbeat).
func TestHeartbeatEpochRollbackRefusedThenRecovered_6169(t *testing.T) {
	e := newLatchEnv(t)
	e.liveRun(e.captureIncarnation(0x44E0, 9_300_000_000_000_000, epochFramesPerIncarnation), "peer on an epoch-capable build")

	// Operator rolls the peer back to a pre-#6169 build: fresh session, fresh
	// counter, no epoch section. Refused — indistinguishable on the wire from a
	// replayed pre-upgrade capture.
	rolledBack := e.captureIncarnation(0x44FF, 0, epochFramesPerIncarnation)
	for i, f := range rolledBack {
		if e.feed(f) {
			t.Fatalf("rolled-back peer frame %d was admitted — the latch is not engaging", i)
		}
	}

	// Documented recovery: clear the persisted floor, restart xpfd.
	if err := os.Remove(e.floorPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	e.restartDaemon()
	if e.r.auth.peerEpochLatched() {
		t.Fatal("clearing the persisted floor must disarm the latch")
	}
	e.liveRun(rolledBack, "rolled-back peer after the operator cleared the floor")
}

// TestHeartbeatEpochImplausibleValueCannotLockOut_6169 pins the one-way-door
// guard. An epoch outside the plausibility band must never become the floor —
// latching, say, MaxUint64 would reject every subsequent genuine frame forever.
// It still satisfies the latch, because the peer demonstrably emits epochs.
func TestHeartbeatEpochImplausibleValueCannotLockOut_6169(t *testing.T) {
	e := newLatchEnv(t)

	// A frame carrying an absurd epoch is accepted (it is MAC-authentic) but
	// must not raise the floor.
	if !e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0x55E0, 1, math.MaxUint64)) {
		t.Fatal("a MAC-authentic frame with an implausible epoch should not be rejected")
	}
	if got := e.r.auth.peerEpochFloor(); got != 0 {
		t.Fatalf("floor = %d, want 0 — an implausible epoch must never be latched as the floor", got)
	}
	if !e.r.auth.peerEpochLatched() {
		t.Fatal("an epoch section, even an implausible one, proves the peer emits epochs")
	}
	// The genuine peer with an ordinary epoch is still accepted — no lockout.
	e.liveRun(e.captureIncarnation(0x55E1, 9_400_000_000_000_000, epochFramesPerIncarnation), "genuine peer after an implausible epoch")
	// And nothing implausible reached stable storage.
	if raw, err := os.ReadFile(e.floorPath); err == nil {
		if got, _ := strconv.ParseUint(string(raw[:len(raw)-1]), 10, 64); !epochUsableAsFloor(got) {
			t.Fatalf("implausible floor %d was persisted", got)
		}
	}
}

// TestHeartbeatEpochFloorFailsOpen_6169 pins that every receiver-side storage
// fault fails OPEN. A node that cannot read its own floor must start
// permissive, not start refusing its peer: the latch exists to stop a replay,
// and trading a replay for a self-inflicted split-brain is not a trade worth
// making.
func TestHeartbeatEpochFloorFailsOpen_6169(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"corrupt", "not-a-number"},
		{"implausible", strconv.FormatUint(math.MaxUint64, 10)},
		{"zero", "0"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLatchEnv(t)
			if err := os.WriteFile(e.floorPath, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			e.restartDaemon()
			if e.r.auth.peerEpochLatched() {
				t.Fatalf("an unreadable floor (%q) must leave the receiver UNLATCHED", tc.content)
			}
			if got := e.r.auth.peerEpochFloor(); got != 0 {
				t.Fatalf("floor = %d, want 0", got)
			}
			// Permissive: a not-yet-upgraded peer still works.
			e.liveRun(e.captureIncarnation(0x66E0, 0, epochFramesPerIncarnation), "legacy peer after a corrupt floor")
		})
	}

	// A floor that cannot be WRITTEN must not reject anything either — the
	// in-memory floor still works, it just does not survive a restart.
	t.Run("unwritable_path_still_admits", func(t *testing.T) {
		e := newLatchEnv(t)
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		e.floorPath = filepath.Join(blocker, "sub", "floor")
		e.primeFromDisk()
		e.liveRun(e.captureIncarnation(0x77E0, 9_500_000_000_000_000, epochFramesPerIncarnation), "peer with an unwritable local floor")
		if got := e.r.auth.peerEpochFloor(); got != 9_500_000_000_000_000 {
			t.Fatalf("in-memory floor = %d, want the advanced value even when the write fails", got)
		}
	})
}
