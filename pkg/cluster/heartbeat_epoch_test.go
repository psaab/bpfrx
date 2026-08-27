package cluster

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #6169: an on-link attacker holding heartbeatReplaySessions+1 or more captured
// authenticated peer incarnations can churn the bounded session ring by REPLAY
// ALONE and sustain forged peer liveness indefinitely. The signed boot epoch
// gives the receiver an order over incarnations and closes it. That order is
// total only while the sender's clock advances monotonically across boots — a
// backward step larger than bootEpochMaxSkew sorts a later incarnation below an
// earlier one (#6711).
//
// THAT DIRECTION IS NOT SAFE, and this header said it was ("refuses a genuine
// peer rather than admitting a retired one"). Both halves fail together: after
// the regression the highest epoch on the wire belongs to a RETIRED incarnation,
// so an archived frame from it is ADMITTED and raises the floor, and the genuine
// current incarnation is then refused. TestArchivedEpochPoisonsAFreshFloor_6711
// measures exactly that. What the floor still buys is that one retired
// incarnation cannot sustain the churn indefinitely — it emits one session
// (#6169 Stage 0), so the ring's watermark closes the repeat.
//
// These tests drive the REAL readLoop auth gate over REAL signed frames.

// epochEnv is one node's view of the control channel: a Manager plus whichever
// heartbeat receiver is currently installed.
type epochEnv struct {
	t   *testing.T
	m   *Manager
	r   *heartbeatReceiver
	key []byte
}

// epochTestPSK is the control-link PSK every epoch fixture is keyed with. One
// constant, installed on the MANAGER, because feed now delegates to admitFrame
// and admitFrame reads the key from the Manager exactly as production does. A
// helper holding its own private copy of the key would put the duplication back
// one level down.
var epochTestPSK = []byte("cluster-shared-secret")

// epochGateManager is a Manager on a KEYED cluster — the only configuration in
// which the boot epoch exists at all, since the section marker is key-derived.
//
// It deliberately does NOT redirect bootEpochPath: nothing on the gate path
// (admitFrame, handlePeerHeartbeat) touches the epoch store. Only StartHeartbeat
// and heartbeatSender.send resolve an epoch, and a fixture that drives either of
// those must use keyedEpochManager, which points the path at a per-test file and
// joins the refine worker.
func epochGateManager() *Manager { return epochGateManagerWithKey(epochTestPSK) }

// epochGateManagerWithKey is epochGateManager under a NAMED key, for the
// rotation fixtures: a daemon restart re-reads the committed PSK, so a restart
// after a rotation must come up on the ROTATED key, not the original one.
func epochGateManagerWithKey(key []byte) *Manager {
	m := NewManager(0, 42)
	m.mu.Lock()
	m.controlAuthKey = key
	m.mu.Unlock()
	return m
}

func newEpochEnv(t *testing.T) *epochEnv {
	t.Helper()
	m := epochGateManager()
	e := &epochEnv{t: t, m: m, key: m.controlLinkAuthKey()}
	e.restartHeartbeat()
	return e
}

// restartHeartbeat models what StartHeartbeat/RestartHeartbeat do to the
// receiver: drop the old one and install a brand-new one from
// newHeartbeatReceiver. No sockets or goroutines; the read path is driven
// directly.
func (e *epochEnv) restartHeartbeat() {
	e.t.Helper()
	e.r = newHeartbeatReceiver(e.m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	e.r.startedAt = time.Now().Add(-2 * heartbeatStartupGrace)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
}

// feed pushes one raw frame through the gate readLoop applies, by CALLING it —
// heartbeatReceiver.admitFrame is the single implementation both use. It
// reports whether the frame was accepted.
//
// It used to re-implement that gate line-for-line and assert equivalence in a
// prose comment. That is why severing the receiver's epoch read left every
// epoch test green: the tests were exercising the copy. Delegation makes the
// equivalence structural instead of asserted — see admitFrame.
func (e *epochEnv) feed(frame []byte) bool {
	e.t.Helper()
	pkt, err := UnmarshalHeartbeat(frame)
	if err != nil {
		e.t.Fatalf("unmarshal: %v", err)
	}
	return e.r.admitFrame(frame, pkt)
}

// rotateKey models the operator rotating the control-link PSK on this node: the
// committed key changes, so the RECEIVER verifies with the new one from the next
// frame on, and the peer signs with it too.
//
// BOTH halves, because admitFrame reads the key from the Manager exactly as
// production does. A fixture that changed only its own signing key would leave
// production verifying with the OLD one, so an archived frame signed under that
// old key still verified — and every "rotation retires the attacker's capture"
// assertion was measuring nothing. That is what this fixture did before the
// gate was deduplicated, and it is why restating a production gate in a test
// helper is not a neutral convenience.
func (e *epochEnv) rotateKey(key []byte) {
	e.t.Helper()
	e.key = key
	e.m.mu.Lock()
	e.m.controlAuthKey = key
	e.m.mu.Unlock()
}

// captureIncarnation builds the authenticated frames an on-link attacker
// records off the wire for ONE peer daemon incarnation: n heartbeats sharing
// one session id and one boot epoch, with a monotonic counter. epoch == 0
// produces legacy (pre-#6169) frames that carry no epoch section.
func (e *epochEnv) captureIncarnation(session, epoch uint64, n int) [][]byte {
	e.t.Helper()
	frames := make([][]byte, 0, n)
	for c := 1; c <= n; c++ {
		frames = append(frames, marshalHeartbeatAuthEpoch(samplePkt(), e.key, session, uint64(c), epoch))
	}
	return frames
}

// liveRun feeds a captured incarnation as the genuine peer would send it, and
// fails if any frame is rejected — a genuine peer must never be locked out.
func (e *epochEnv) liveRun(frames [][]byte, what string) {
	e.t.Helper()
	for i, f := range frames {
		if !e.feed(f) {
			e.t.Fatalf("genuine frame %d of %s was REJECTED — a live peer must never be locked out", i, what)
		}
	}
}

// replayAll replays every captured frame `rounds` times round-robin across
// incarnations (the FIFO ring-churn pattern) and reports how many were admitted.
func (e *epochEnv) replayAll(caps [][][]byte, rounds int) (admitted, total int) {
	e.t.Helper()
	for r := 0; r < rounds; r++ {
		for _, frames := range caps {
			for _, f := range frames {
				total++
				if e.feed(f) {
					admitted++
				}
			}
		}
	}
	return admitted, total
}

const epochFramesPerIncarnation = 5

// TestHeartbeatBootEpochClosesSustainedReplay_6169 is the #6169 fail-on-revert
// gate.
//
// It first reproduces the issue's measured baseline on LEGACY (epoch-less)
// frames — heartbeatReplaySessions recordings are fully rejected, one more is
// sustained 100% — and then shows the signed boot epoch closing exactly that
// case.
//
// RED-on-revert: the fix is the epoch floor in heartbeatAuthState.admitAuthed
// (`if epoch < s.highEpoch { return false }` plus raising the floor). Delete
// the floor comparison — or move it AFTER the s.replay.admit call, the ordering
// bug that failed review on the earlier attempt — and the epoch subtest goes
// back to sustained admits and FAILS.
func TestHeartbeatBootEpochClosesSustainedReplay_6169(t *testing.T) {
	// Legacy frames, heartbeatReplaySessions recordings: the ring holds every
	// session, so every replay is at/below its watermark and rejected.
	t.Run("baseline_legacy_at_ring_capacity_rejected", func(t *testing.T) {
		e := newEpochEnv(t)
		caps := make([][][]byte, 0, heartbeatReplaySessions)
		for i := 0; i < heartbeatReplaySessions; i++ {
			frames := e.captureIncarnation(uint64(0x1000+i), 0, epochFramesPerIncarnation)
			e.liveRun(frames, "legacy capture")
			caps = append(caps, frames)
		}
		admitted, total := e.replayAll(caps, 2)
		if admitted != 0 {
			t.Fatalf("baseline: %d/%d replays admitted at ring capacity, want 0", admitted, total)
		}
	})

	// Legacy frames, one MORE than the ring holds: FIFO eviction always leaves
	// exactly one just-evicted session to replay back in as never-seen, so the
	// churn is self-sustaining. This subtest documents the vulnerability and is
	// expected to keep passing after the fix — legacy frames still take the
	// legacy path (dual-accept).
	t.Run("baseline_legacy_over_ring_capacity_is_sustained", func(t *testing.T) {
		e := newEpochEnv(t)
		caps := make([][][]byte, 0, heartbeatReplaySessions+1)
		for i := 0; i <= heartbeatReplaySessions; i++ {
			frames := e.captureIncarnation(uint64(0x2000+i), 0, epochFramesPerIncarnation)
			e.liveRun(frames, "legacy capture")
			caps = append(caps, frames)
		}
		admitted, total := e.replayAll(caps, 2)
		if admitted != total {
			t.Fatalf("baseline: %d/%d replays admitted over ring capacity, want all "+
				"(this subtest asserts the vulnerability the epoch closes)", admitted, total)
		}
	})

	// THE FIX. Same attack, same number of captured incarnations, but each
	// incarnation now signs its own increasing boot epoch (strictly so here,
	// where the epochs are constructed in order; the sender is not strictly
	// increasing across a backward clock step larger than bootEpochMaxSkew —
	// #6711). Once the receiver has seen the newest incarnation, every captured
	// retired one is below the floor and is rejected before it can touch the
	// ring.
	t.Run("epoch_rejects_every_retired_incarnation", func(t *testing.T) {
		e := newEpochEnv(t)
		const n = heartbeatReplaySessions + 8 // comfortably past the churn threshold
		caps := make([][][]byte, 0, n)
		for i := 0; i < n; i++ {
			// A real daemon restart draws a fresh session AND a strictly higher
			// epoch (bootEpochSeed + refineBootEpoch).
			frames := e.captureIncarnation(uint64(0x3000+i), uint64(1_000+i), epochFramesPerIncarnation)
			e.liveRun(frames, "epoch capture")
			caps = append(caps, frames)
		}
		admitted, total := e.replayAll(caps, 3)
		if admitted != 0 {
			t.Fatalf("epoch guard: %d/%d replays admitted, want 0 — the >=%d-recording "+
				"sustained replay is NOT closed", admitted, total, heartbeatReplaySessions+1)
		}
		if got := e.r.auth.peerEpochFloor(); got != uint64(1_000+n-1) {
			t.Fatalf("epoch floor = %d, want %d (a replayed frame must never move the floor)",
				got, 1_000+n-1)
		}
	})

	// NEGATIVE CONTROL. This must pass both WITH and WITHOUT the fix: a
	// genuinely newer incarnation, arriving after the replay barrage, is still
	// admitted. It proves the gate rejects replays specifically rather than
	// wedging the control channel — a guard that rejected everything would also
	// make the subtest above pass.
	t.Run("negative_control_live_peer_still_admitted", func(t *testing.T) {
		e := newEpochEnv(t)
		const n = heartbeatReplaySessions + 8
		caps := make([][][]byte, 0, n)
		for i := 0; i < n; i++ {
			frames := e.captureIncarnation(uint64(0x4000+i), uint64(2_000+i), epochFramesPerIncarnation)
			e.liveRun(frames, "epoch capture")
			caps = append(caps, frames)
		}
		e.replayAll(caps, 2)
		// The peer reboots for real: fresh session, strictly higher epoch.
		live := e.captureIncarnation(0x4FFF, 9_999, epochFramesPerIncarnation)
		e.liveRun(live, "post-replay genuine reboot")
	})
}

// TestHeartbeatEpochRejectionDoesNotChurnRing_6169 pins the ORDERING that makes
// the fix work: the epoch floor is consulted BEFORE the session ring.
//
// heartbeatAuthReplay.admit RECORDS a never-seen session as a side effect and
// evicts the oldest watermark FIFO. If the epoch were checked after it, a
// rejected replay would still evict live watermarks — so replaying enough
// retired frames would flush the ring and let an ordinary within-epoch replay
// back in. This is the bypass that failed review on the earlier attempt.
func TestHeartbeatEpochRejectionDoesNotChurnRing_6169(t *testing.T) {
	e := newEpochEnv(t)

	// The live peer's current incarnation, seen genuinely.
	const liveSession, liveEpoch = uint64(0x11FE), uint64(5_000)
	live := e.captureIncarnation(liveSession, liveEpoch, epochFramesPerIncarnation)
	e.liveRun(live, "live incarnation")

	// A ringful-and-then-some of RETIRED lower-epoch incarnations is replayed.
	// Every one must be rejected, and none may evict the live watermark.
	for i := 0; i < heartbeatReplaySessions*3; i++ {
		retired := e.captureIncarnation(uint64(0x6000+i), uint64(100+i), epochFramesPerIncarnation)
		for _, f := range retired {
			if e.feed(f) {
				t.Fatalf("retired-epoch frame (incarnation %d) was admitted", i)
			}
		}
	}

	// The live incarnation's own already-seen frames must STILL be rejected. If
	// the rejected replays had churned the ring, liveSession's watermark would
	// have been evicted and these would be admitted as never-seen.
	for i, f := range live {
		if e.feed(f) {
			t.Fatalf("live-incarnation frame %d was re-admitted — the rejected replays "+
				"churned the ring (epoch checked after the ring insert)", i)
		}
	}
	// And the live peer itself still advances normally.
	next := marshalHeartbeatAuthEpoch(samplePkt(), e.key, liveSession, uint64(len(live)+1), liveEpoch)
	if !e.feed(next) {
		t.Fatal("live peer's next genuine frame was rejected")
	}
}

// TestHeartbeatEpochDualAcceptMigration_6169 covers the rolling-upgrade window
// in BOTH directions. A mixed-version cluster that stops passing heartbeats is
// a split-brain, which is worse than the replay this closes, so both halves
// must interoperate unchanged.
func TestHeartbeatEpochDualAcceptMigration_6169(t *testing.T) {
	key := []byte("cluster-shared-secret")

	// Old peer -> new receiver: a legacy frame carries no epoch section and is
	// still accepted, taking the legacy session-ring path.
	t.Run("legacy_frame_accepted_by_epoch_receiver", func(t *testing.T) {
		e := newEpochEnv(t)
		for c := 1; c <= 3; c++ {
			frame := MarshalHeartbeatAuth(samplePkt(), key, 0x7777, uint64(c))
			if _, ok := heartbeatFrameEpoch(frame, key); ok {
				t.Fatal("legacy frame reported an epoch section")
			}
			if !e.feed(frame) {
				t.Fatalf("legacy frame %d rejected by an epoch-capable receiver", c)
			}
		}
	})

	// New peer -> new receiver.
	t.Run("epoch_frame_accepted_by_epoch_receiver", func(t *testing.T) {
		e := newEpochEnv(t)
		for c := 1; c <= 3; c++ {
			frame := marshalHeartbeatAuthEpoch(samplePkt(), key, 0x8888, uint64(c), 4_242)
			got, ok := heartbeatFrameEpoch(frame, key)
			if !ok || got != 4_242 {
				t.Fatalf("epoch readback = (%d,%v), want (4242,true)", got, ok)
			}
			if !e.feed(frame) {
				t.Fatalf("epoch frame %d rejected", c)
			}
		}
	})

	// New peer -> OLD receiver. This is the half that split the cluster in the
	// earlier attempt (#6370), which appended the epoch AFTER the auth trailer:
	// an old receiver looking for "XPFA" at len-52 then found body bytes, read
	// the frame as unsigned, and an enforcing old peer rejected every frame.
	// With the section BEFORE the trailer, an old receiver must still locate the
	// trailer, verify the MAC over the bytes the new sender signed, and decode
	// an identical packet.
	t.Run("epoch_frame_accepted_by_legacy_receiver", func(t *testing.T) {
		legacy := MarshalHeartbeatAuth(samplePkt(), key, 0x9999, 7)
		v2 := marshalHeartbeatAuthEpoch(samplePkt(), key, 0x9999, 7, 4_242)

		// What a pre-#6169 receiver does, verbatim.
		session, counter, present := heartbeatAuthTrailer(v2)
		if !present {
			t.Fatal("legacy receiver could not locate the auth trailer in a v2 frame")
		}
		if session != 0x9999 || counter != 7 {
			t.Fatalf("legacy receiver read nonce (%#x,%d), want (0x9999,7)", session, counter)
		}
		if !verifyHeartbeatMAC(v2, key) {
			t.Fatal("legacy receiver failed to verify the MAC of a v2 frame")
		}
		gotPkt, err := UnmarshalHeartbeat(v2)
		if err != nil {
			t.Fatalf("legacy receiver failed to decode a v2 frame: %v", err)
		}
		wantPkt, err := UnmarshalHeartbeat(legacy)
		if err != nil {
			t.Fatalf("decode legacy frame: %v", err)
		}
		// Whole-struct compare: the parse is offset-driven, so any byte the
		// epoch section displaced would surface somewhere in the decode.
		if !reflect.DeepEqual(gotPkt, wantPkt) {
			t.Fatalf("legacy receiver decoded a v2 frame differently:\n got %+v\nwant %+v", gotPkt, wantPkt)
		}
		// The epoch really is inside the signed span: flipping a bit in it must
		// break the MAC an OLD receiver checks, so it cannot be forged even
		// against a peer that ignores it.
		tampered := append([]byte(nil), v2...)
		epochAt := len(tampered) - heartbeatAuthTrailerSize - heartbeatEpochFieldSize
		tampered[epochAt] ^= 0x01
		if verifyHeartbeatMAC(tampered, key) {
			t.Fatal("epoch is OUTSIDE the signed span — it is forgeable")
		}
	})

	// epoch == 0 is the "advertise no epoch" sentinel and must produce a
	// byte-identical legacy frame, so a node that cannot persist an epoch is
	// wire-indistinguishable from a not-yet-upgraded one.
	t.Run("zero_epoch_is_byte_identical_to_legacy", func(t *testing.T) {
		legacy := MarshalHeartbeatAuth(samplePkt(), key, 0xABC, 3)
		zero := marshalHeartbeatAuthEpoch(samplePkt(), key, 0xABC, 3, 0)
		if string(legacy) != string(zero) {
			t.Fatalf("epoch==0 frame differs from legacy (%d vs %d bytes)", len(zero), len(legacy))
		}
	})
}

// TestHeartbeatEpochMarkerIsKeyDerived_6169 pins the marker's two required
// properties: it is a PRF value (so an attacker without the PSK cannot make a
// legacy body read as an epoch section), and a frame signed under a different
// key never reads as carrying one.
func TestHeartbeatEpochMarkerIsKeyDerived_6169(t *testing.T) {
	keyA := []byte("cluster-shared-secret")
	keyB := []byte("a-different-secret")

	if string(heartbeatEpochMarker(keyA)) == string(heartbeatEpochMarker(keyB)) {
		t.Fatal("marker is not key-derived: two different PSKs produced the same marker")
	}
	frame := marshalHeartbeatAuthEpoch(samplePkt(), keyA, 1, 1, 12345)
	if _, ok := heartbeatFrameEpoch(frame, keyB); ok {
		t.Fatal("a frame signed under key A reported an epoch section under key B")
	}
	if _, ok := heartbeatFrameEpoch(frame, nil); ok {
		t.Fatal("keyless read reported an epoch section")
	}
	// A short frame (canonical zero-RG body is 13 bytes) must read as "no
	// epoch" rather than slicing out of range.
	minimal := &HeartbeatPacket{NodeID: 1, ClusterID: 42}
	short := MarshalHeartbeatAuth(minimal, keyA, 1, 1)
	if _, ok := heartbeatFrameEpoch(short, keyA); ok {
		t.Fatal("a minimal legacy frame reported an epoch section")
	}
	if _, ok := heartbeatFrameEpoch(short[:heartbeatAuthTrailerSize-1], keyA); ok {
		t.Fatal("a runt frame reported an epoch section")
	}
	// The SMALLEST REAL v2 frame must still read its epoch back. The guard is a
	// bounds-safety floor (heartbeatHeaderSize+16 = 25), and the smallest body
	// a v2 sender can actually produce is larger — a canonical zero-RG,
	// zero-monitor, empty-version body is 13 bytes, so bodyEnd is 29. Those
	// numbers are asserted here so the slack is visible: a guard raised above
	// 29 would silently drop every epoch from a zero-RG node, and the gate would
	// look healthy while protecting nothing.
	smallest := marshalHeartbeatAuthEpoch(minimal, keyA, 1, 1, 777)
	bodyEnd := len(smallest) - heartbeatAuthTrailerSize
	if want := 13 + heartbeatEpochSectionSize; bodyEnd != want {
		t.Fatalf("smallest v2 body is %d bytes, expected %d — the wire layout changed, "+
			"so re-derive the heartbeatFrameEpoch length guard", bodyEnd, want)
	}
	if got, ok := heartbeatFrameEpoch(smallest, keyA); !ok || got != 777 {
		t.Fatalf("smallest v2 frame epoch = (%d,%v), want (777,true) — the body-length "+
			"guard is too strict and drops epochs from a zero-RG node", got, ok)
	}
}

// TestHeartbeatEpochFrameFitsWireCap_6169 pins the tail reserve. The epoch
// section is 16 bytes ahead of the 52-byte auth trailer, so a maximal frame
// must reserve 68 — reserving only the trailer lets the frame exceed
// maxHeartbeatSize, which the receiver's read buffer silently truncates,
// destroying the MAC and making an enforcing peer reject every heartbeat.
func TestHeartbeatEpochFrameFitsWireCap_6169(t *testing.T) {
	key := []byte("cluster-shared-secret")
	pkt := samplePkt()
	pkt.Groups = nil
	for i := 0; i < maxHeartbeatGroups; i++ {
		pkt.Groups = append(pkt.Groups, HeartbeatGroup{GroupID: uint8(i), Priority: 200, Weight: 255})
	}
	pkt.Monitors = nil
	for i := 0; i < 400; i++ {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{RGID: 0, Weight: 10, Up: true, Interface: "ge-0-0-0.4094"})
	}
	frame := marshalHeartbeatAuthEpoch(pkt, key, 1, 1, 999)
	if len(frame) > maxHeartbeatSize {
		t.Fatalf("maximal epoch frame is %d bytes, exceeds the %d-byte wire cap "+
			"(receiver would truncate it and reject the MAC)", len(frame), maxHeartbeatSize)
	}
	if !verifyHeartbeatMAC(frame, key) {
		t.Fatal("maximal epoch frame does not verify")
	}
	if got, ok := heartbeatFrameEpoch(frame, key); !ok || got != 999 {
		t.Fatalf("maximal epoch frame epoch = (%d,%v), want (999,true)", got, ok)
	}
}

// TestNextBootEpochMonotonic_6169 covers the epoch SEED: resolution, first
// boot, a backward clock step, and a persist failure.
func TestBootEpochMonotonic_6169(t *testing.T) {
	// First boot with no persisted value seeds from the wall clock, well above
	// any low retired counter, and persists.
	t.Run("first_boot_seeds_from_wall_clock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sub", "ha-boot-epoch")
		before := uint64(time.Now().UnixNano())
		got, ok := bootEpochIncarnation(path)
		if !ok {
			t.Fatal("first boot failed to persist")
		}
		if got < before {
			t.Fatalf("epoch %d is below the wall clock at call time %d", got, before)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("epoch not persisted: %v", err)
		}
	})

	// Restarts are STRICTLY increasing, including back-to-back ones, UNDER A
	// MONOTONIC CLOCK — which is what this subtest runs (bootEpochIncarnation
	// seeds from the real time.Now()). That scope is the whole claim: the
	// persisted term is bounded, so a backward step larger than
	// bootEpochMaxSkew regresses the epoch instead (#6711, and the
	// value_beyond_the_forward_bound_is_not_chained_from subtest above).
	//
	// IT DOES NOT ISOLATE THE WALL-CLOCK TERM, and an earlier revision of this
	// comment claimed it pinned that term's nanosecond resolution. It cannot:
	// every iteration here persists successfully, so `persisted+1` supplies
	// strictness whenever the seed does not. Verified: rounding bootEpochSeed
	// to whole seconds leaves this subtest — and the entire package — green.
	// The seed's own resolution is pinned separately, by
	// TestBootEpochSeedResolutionIsFinerThanARestart_6669.
	t.Run("restarts_strictly_increase", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		prev := uint64(0)
		for i := 0; i < 200; i++ {
			got, ok := bootEpochIncarnation(path)
			if !ok {
				t.Fatalf("restart %d failed to persist", i)
			}
			if got <= prev {
				t.Fatalf("restart %d: epoch %d did not exceed previous %d", i, got, prev)
			}
			prev = got
		}
	})

	// A wall clock that steps BACKWARDS across a reboot (RTC skew, an NTP step,
	// a manual set-back) must not regress the epoch, or the peer would reject a
	// genuinely restarted node's heartbeats. persisted+1 dominates.
	t.Run("backward_clock_step_does_not_regress", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		// A persisted value slightly ahead of now models "the clock has since
		// stepped back below the last epoch" — the realistic shape of RTC skew
		// or an NTP correction.
		ahead := uint64(time.Now().Add(time.Hour).UnixNano())
		if err := os.WriteFile(path, []byte(strconv.FormatUint(ahead, 10)), 0o644); err != nil {
			t.Fatal(err)
		}
		got, ok := bootEpochIncarnation(path)
		if !ok {
			t.Fatal("persist failed")
		}
		if got != ahead+1 {
			t.Fatalf("epoch = %d, want %d (persisted+1 must dominate a backward clock step)", got, ahead+1)
		}
	})

	// THE TRADE THE FORWARD BOUND MAKES, pinned so it is deliberate rather than
	// discovered. A persisted value more than bootEpochMaxSkew ahead of now is
	// NOT chained from, so a backward clock step larger than the skew allowance
	// does regress this node's epoch.
	//
	// WHY THE RATIONALE HERE IS NARROWER THAN IT LOOKS. An earlier revision of
	// this comment justified the trade by asserting that such a value "is only
	// reachable if this node's own clock was the wrong one when it persisted —
	// in which case the peer refused and never latched it, so nothing is locked
	// out". That is FALSE, and a characterization test whose stated reason is
	// wrong is worse than one with no reason at all: it stops the next reader
	// questioning the behaviour. There is a second, entirely benign way to
	// reach it, with intact storage and a CORRECT earlier clock:
	//
	//	1. incarnation A runs at the right time T, persists T; the peer
	//	   latches floor T — so something IS locked out;
	//	2. incarnation B starts with its clock at T-2h, still comfortably
	//	   above epochClockSaneFloor, and publishes T-2h;
	//	3. refinement rejects the intact, correct persisted T for exceeding
	//	   now+bootEpochMaxSkew, leaves prev=0, and overwrites the file with
	//	   T-2h;
	//	4. the peer refuses every B frame below floor T, and a later NTP
	//	   correction cannot move B's already-published epoch — a restart is
	//	   needed.
	//
	// So the honest statement of the trade is: BOTH outcomes are lockouts, and
	// the choice is between one that is recoverable and one that is not.
	// Chaining from an out-of-range value would strand this node permanently
	// above the range its peer will ever accept, with no way back down.
	//
	// DECLINING IS STILL A LOCKOUT, AND NOT ONE THAT "ANY RESTART ON EITHER NODE
	// CLEARS" — an earlier revision of this comment said that, and it is false
	// in both directions. Restarting the SENDER while its clock is still T-2h
	// does not clear it: step 3 above overwrote the file with T-2h, so the next
	// incarnation re-publishes from the same bad clock and stays below floor T
	// (measured in TestArchivedEpochPoisonsAFreshFloor_6711). Restarting the
	// RECEIVER does clear the floor, but one archived frame from incarnation A
	// re-raises it, at one re-injection per restart — the residual 5 shape
	// applied to the floor instead of the latch. What actually recovers is
	// fixing the clock (then restarting the sender), or rotating the PSK before
	// the receiver restart. Recoverable still beats unrecoverable — but it is
	// not free, it is not confined to a node that was already misconfigured, and
	// it is not a one-command fix.
	//
	// UPDATED FOR THE #6711 FIX. The paragraph above used to end "This subtest
	// pins today's behaviour, not the desired one", with the behavioural fix
	// deferred to #6711. That fix has landed, so this pins the new semantics.
	//
	// Declining to CHAIN is unchanged and is still the important half: chaining
	// from a value that far ahead strands this node above the range its peer
	// will ever accept, which is the unrecoverable direction.
	//
	// What changed is that the file is no longer HEALED in this case. A value
	// inside bootEpochPreserveMaxSkew is indistinguishable, from here, between
	// "written by a clock that ran ahead" and "written correctly before OUR
	// clock stepped back", and destroying it in the second case is what made a
	// single backward step outlive every restart. Recovery is now by the clock
	// advancing past the bound rather than by the file being flattened, which
	// the pinned-clock leg below shows directly.
	t.Run("value_beyond_the_forward_bound_is_not_chained_from", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		farAhead := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
		if err := os.WriteFile(path, []byte(strconv.FormatUint(farAhead, 10)), 0o644); err != nil {
			t.Fatal(err)
		}
		// Driven through refineBootEpoch directly rather than through
		// bootEpochIncarnation: that helper reports "persisted" as "the file
		// ends up holding what we published", which is legitimately FALSE in
		// the preserve case — the whole point is that the file keeps the OTHER
		// value. Using it here would read a correct preserve as a failed write.
		var pub atomic.Uint64
		pub.Store(bootEpochSeed())
		refineBootEpoch(path, &pub, 0)
		got := pub.Load()
		if got >= farAhead {
			t.Fatalf("epoch = %d, chained from an out-of-range persisted value %d — "+
				"this node could never come back down into its peer's accepted range", got, farAhead)
		}
		if !epochOrderable(got, time.Now().UnixNano()) {
			t.Fatalf("reseeded epoch %d is itself out of range", got)
		}
		// PRESERVED, not healed (#6711): the value may be an intact predecessor
		// this node's clock has stepped back behind, and overwriting it is what
		// makes the lockout survive restarts.
		if onDisk := readEpochFile(t, path); onDisk != farAhead {
			t.Fatalf("persisted %d, want the PRESERVED %d — a value inside "+
				"bootEpochPreserveMaxSkew must survive a pass that declines to chain from it",
				onDisk, farAhead)
		}
		// And once the clock catches up, chaining resumes from exactly that
		// preserved value — the recovery the preservation exists for.
		withPinnedEpochClock(t, int64(farAhead))
		var caughtUp atomic.Uint64
		caughtUp.Store(farAhead)
		refineBootEpoch(path, &caughtUp, 0)
		if next := caughtUp.Load(); next <= farAhead {
			t.Fatalf("with the clock caught up, refinement published %d, want a value above the "+
				"preserved %d — chaining must resume once the value is back in range", next, farAhead)
		}
	})

	// A corrupt persisted value degrades to the wall-clock seed rather than
	// failing heartbeat start.
	t.Run("corrupt_state_degrades_to_wall_clock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		if err := os.WriteFile(path, []byte("not-a-number"), 0o644); err != nil {
			t.Fatal(err)
		}
		before := uint64(time.Now().UnixNano())
		got, ok := bootEpochIncarnation(path)
		if !ok {
			t.Fatal("persist failed")
		}
		if got < before {
			t.Fatalf("epoch %d is below the wall clock %d", got, before)
		}
	})

	// A PERSIST FAILURE MUST NOT SUPPRESS EMISSION. This is the property that
	// keeps the downgrade latch safe: if a storage fault made a healthy node
	// emit epochless frames, a latched peer would refuse a LIVE node and the
	// latch would have manufactured a split-brain. So the epoch is still
	// returned (and still advertised) — only its DURABILITY is lost, which at
	// worst costs monotonicity across a simultaneous backward clock step.
	t.Run("persist_failure_still_yields_a_usable_epoch", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		before := uint64(time.Now().UnixNano())
		// The parent component is a regular file, so the state dir cannot be
		// created — a failure mode that holds even when running as root.
		got, persisted := bootEpochIncarnation(filepath.Join(blocker, "sub", "ha-boot-epoch"))
		if persisted {
			t.Fatalf("persist failure reported durable (epoch %d)", got)
		}
		if got < before {
			t.Fatalf("persist failure returned epoch %d, below the wall clock %d — a node that "+
				"cannot write must still ADVERTISE an epoch or a latched peer refuses it", got, before)
		}
	})

	// A corrupt / hand-edited value near MaxUint64 must not be chained from.
	// Incrementing it saturates on one boot and REGRESSES on the next
	// (MaxUint64+1 overflows, so the wall clock wins), and a peer that latched
	// MaxUint64 would then refuse this node forever — a permanent, self-
	// inflicted lockout. Ignoring the implausible value heals the file instead.
	t.Run("implausible_persisted_value_does_not_regress", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		if err := os.WriteFile(path, []byte(strconv.FormatUint(math.MaxUint64-1, 10)), 0o644); err != nil {
			t.Fatal(err)
		}
		first, ok1 := bootEpochIncarnation(path)
		second, ok2 := bootEpochIncarnation(path)
		if !ok1 || !ok2 {
			t.Fatalf("persist failed (%v, %v)", ok1, ok2)
		}
		if second <= first {
			t.Fatalf("epoch REGRESSED across restarts: %d then %d — a peer that latched the "+
				"first value would refuse this node forever", first, second)
		}
		if !epochUsableAsFloor(first) || !epochUsableAsFloor(second) {
			t.Fatalf("implausible epochs emitted: %d, %d", first, second)
		}
	})
}

// TestEpochPlausibleBound_6169 pins the one-sided sanity bound on what may be
// latched as a floor. The floor is a ONE-WAY DOOR, so a bogus far-future value
// locks the peer out permanently; a LOW value is merely permissive, which is
// why the bound is upper-only (an appliance with a dead RTC must not be
// refused, and the bound must not depend on the receiver's own clock).
func TestEpochPlausibleBound_6169(t *testing.T) {
	if want := uint64(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()); epochPlausibleMax != want {
		t.Fatalf("epochPlausibleMax = %d, want %d (2200-01-01T00:00:00Z)", epochPlausibleMax, want)
	}
	now := uint64(time.Now().UnixNano())
	if !epochUsableAsFloor(now) {
		t.Fatalf("a present-day wall-clock epoch (%d) must be usable as a floor", now)
	}
	if epochUsableAsFloor(math.MaxUint64) {
		t.Fatal("MaxUint64 must not be usable as a floor")
	}
	if epochUsableAsFloor(0) {
		t.Fatal("the 0 sentinel must not be usable as a floor")
	}
	// A dead RTC (clock at the Unix epoch + a little) is permissive, not
	// locking, and must still be accepted as a floor.
	if !epochUsableAsFloor(1) {
		t.Fatal("a low epoch must remain usable — bounding below would refuse a peer with a dead RTC")
	}
}

// TestHeartbeatBootEpochRefinementCompletes_6169 observes the persistence
// refinement actually running.
//
// This test previously polled until heartbeatBootEpoch returned non-zero. Once
// the epoch was published synchronously — the correct fix for the storage-hang
// finding — that loop exited on its first iteration and the test stopped
// exercising the thing its name claims. It kept passing and guarded nothing.
// The same fix also invalidated its other assertion: it required the epoch to
// be STABLE across calls, but refinement legitimately RAISES it after a
// backward clock step, so that had become a false claim rather than a weak one.
//
// It now joins the worker and checks both halves of the real contract: with no
// refinement needed the published value is untouched and reaches disk, and with
// one needed the value is raised.
func TestHeartbeatBootEpochRefinementCompletes_6169(t *testing.T) {
	t.Run("no_refinement_needed_value_persists_unchanged", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ha-boot-epoch")
		orig := bootEpochPath
		bootEpochPath = path
		t.Cleanup(func() { bootEpochPath = orig })

		m := NewManager(0, 42)
		published := m.heartbeatBootEpoch()
		if published == 0 {
			t.Fatal("no epoch published synchronously")
		}
		// JOIN the worker rather than polling for a value that is already set —
		// this is what makes the test observe the refinement at all, and it also
		// keeps the worker from outliving t.TempDir. bootEpochReady on its own
		// does NOT do the second half; see awaitFirstRefine.
		awaitFirstRefine(t, m, "the refinement worker")

		// It ran: the epoch reached disk.
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("refinement did not persist the epoch: %v", err)
		}
		onDisk, perr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if perr != nil {
			t.Fatalf("persisted value unparseable: %q", raw)
		}
		// Nothing to raise against, so the published value is unchanged and is
		// exactly what was recorded.
		if final := m.heartbeatBootEpoch(); final != published {
			t.Fatalf("epoch changed with no refinement needed: %d then %d", published, final)
		}
		if onDisk != published {
			t.Fatalf("persisted %d, want the published %d", onDisk, published)
		}
	})

	t.Run("refinement_raises_after_a_backward_clock_step", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ha-boot-epoch")
		// A persisted value ahead of now models a clock that has since stepped
		// back below the last epoch — the one case persistence exists for.
		ahead := uint64(time.Now().Add(30 * time.Minute).UnixNano())
		if err := os.WriteFile(path, []byte(strconv.FormatUint(ahead, 10)), 0o644); err != nil {
			t.Fatal(err)
		}
		orig := bootEpochPath
		bootEpochPath = path
		t.Cleanup(func() { bootEpochPath = orig })

		// HOLD THE WORKER UNTIL `published` HAS BEEN READ. heartbeatBootEpoch
		// spawns the refine worker inside bootEpochOnce.Do and only THEN returns
		// m.bootEpoch.Load(), so a worker that wins that race has already raised
		// the value: `published` captures the RAISED epoch, final == published,
		// and the assertion below reds on a perfectly healthy tree. Measured
		// before this park, six concurrent processes at -count=200: 41/1200.
		//
		// The park is on epochFlock, which sits INSIDE withEpochFileLock and
		// therefore strictly before refineBootEpoch's read-modify-write — so
		// while it is held no raise can have happened, and `published` is
		// deterministically the unrefined seed.
		atFlock := make(chan struct{})
		releaseWorker := make(chan struct{})
		var flockOnce sync.Once
		origFlock := epochFlock
		epochFlock = func(fd int, how int) error {
			flockOnce.Do(func() {
				close(atFlock)
				<-releaseWorker
			})
			return origFlock(fd, how)
		}
		t.Cleanup(func() { epochFlock = origFlock })
		var unparkOnce sync.Once
		unpark := func() { unparkOnce.Do(func() { close(releaseWorker) }) }
		t.Cleanup(unpark)

		m := NewManager(0, 42)
		published := m.heartbeatBootEpoch()
		select {
		case <-atFlock:
		case <-time.After(5 * time.Second):
			t.Fatal("the refinement worker never reached the file lock")
		}
		if got := m.heartbeatBootEpoch(); got != published {
			t.Fatalf("the epoch moved from %d to %d while the worker was parked BEFORE the "+
				"file lock; nothing can raise it there, so the park is not where it is "+
				"believed to be", published, got)
		}
		unpark()
		awaitFirstRefine(t, m, "the refinement worker")
		final := m.heartbeatBootEpoch()
		if final <= published {
			t.Fatalf("refinement did not raise the epoch: published %d, final %d "+
				"(persisted %d) — the backward-clock-step protection did not run",
				published, final, ahead)
		}
		if final != ahead+1 {
			t.Fatalf("refined epoch = %d, want %d (persisted+1)", final, ahead+1)
		}
	})
}

// TestBootEpochNeverBlocksOnStorage_6169 is the fail-on-revert gate for the
// availability half of #6169.
//
// The downgrade latch means a peer REJECTS epoch-less frames from a node that
// has proved it emits epochs. So if a storage fault could stop this node
// emitting one, the latch would convert a disk stall into a false peer-death —
// an availability regression on an HA path, caused by the fix. The invariant
// that prevents it: the epoch is published SYNCHRONOUSLY from the wall clock
// with no file access at all, and persistence is a refinement that only ever
// raises it.
//
// RED-on-revert: make heartbeatBootEpoch resolve through the filesystem before
// publishing (the earlier shape) and the first call returns 0 here.
func TestBootEpochNeverBlocksOnStorage_6169(t *testing.T) {
	// A state path that can never be created: the parent component is a regular
	// file, which fails even as root.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := bootEpochPath
	bootEpochPath = filepath.Join(blocker, "sub", "ha-boot-epoch")
	t.Cleanup(func() { bootEpochPath = orig })

	m := NewManager(0, 42)
	before := uint64(time.Now().UnixNano())
	// FIRST call, no waiting: an epoch must already be available.
	got := m.heartbeatBootEpoch()
	if got == 0 {
		t.Fatal("heartbeatBootEpoch returned 0 on the first call — emission is gated on " +
			"storage, so a disk stall would make a latched peer see this healthy node as dead")
	}
	if got < before {
		t.Fatalf("published epoch %d is below the wall clock %d", got, before)
	}
	// And it stays available even though the persist can never succeed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.heartbeatBootEpoch() == 0 {
			t.Fatal("epoch went back to 0 after the failed persist")
		}
		select {
		case <-m.bootEpochReady:
			deadline = time.Now()
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
	// A real signed frame carries it, so a latched peer accepts us.
	key := []byte("cluster-shared-secret")
	frame := marshalHeartbeatAuthEpoch(samplePkt(), key, 1, 1, m.heartbeatBootEpoch())
	if _, present := heartbeatFrameEpoch(frame, key); !present {
		t.Fatal("a node with unwritable state emitted an epoch-less frame")
	}

	// DRAIN. The loop above stops at bootEpochReady, which the worker closes
	// while it is still running — it goes on to read epochRefineBeforeRelease
	// inside releaseBootEpochRefine, and a later test in this package assigns
	// that var. See awaitFirstRefine.
	waitBootEpochIdle(t, m)
}

// TestBootEpochRefinementRaisesAfterBackwardClockStep_6169 pins the other half:
// persistence is a REFINEMENT that still does its one job. After a backward
// clock step the wall-clock seed alone would not clear the previous
// incarnation, so the worker raises the published epoch above it.
func TestBootEpochRefinementRaisesAfterBackwardClockStep_6169(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	// A persisted value slightly ahead of now models a clock that has since
	// stepped back below the last epoch.
	ahead := uint64(time.Now().Add(30 * time.Minute).UnixNano())
	if err := os.WriteFile(path, []byte(strconv.FormatUint(ahead, 10)), 0o644); err != nil {
		t.Fatal(err)
	}
	var published atomic.Uint64
	seed := uint64(time.Now().UnixNano())
	published.Store(seed)

	refineBootEpoch(path, &published, 0)

	if got := published.Load(); got != ahead+1 {
		t.Fatalf("refined epoch = %d, want %d (persisted+1 must dominate a backward clock step)", got, ahead+1)
	}
	// The refined value reached disk, so the next incarnation chains from it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); got != ahead+1 {
		t.Fatalf("persisted %d, want %d", got, ahead+1)
	}
	_ = seed
}

// TestEpochFileLockFailsClosed_6169 is the guard for the lock's failure path.
//
// A lock whose failure path executes the critical section anyway is not a lock:
// it reinstates the concurrent-resolution race precisely when the guard cannot
// fire. Skipping is free here because emission does not depend on it — the
// wall-clock epoch is already published and already on the wire, so all that is
// lost is backward-clock-step protection.
//
// BOTH failure branches are exercised, and the second one needs an injection
// point. Failing the OPEN is easy — point the lock path through a regular file.
// Failing the FLOCK is not: flock(2) on a successfully opened regular file does
// not fail on Linux, so with the open-failure case alone a mutation that ran the
// critical section unlocked on the flock error stayed green (verified: `go build`
// and `go vet` rc=0, this test PASS). epochFlock exists so the guard's scope
// matches its claim.
//
// RED-on-revert: restore `fn()` on either failure path in withEpochFileLock —
// each one reds its own subtest.
func TestEpochFileLockFailsClosed_6169(t *testing.T) {
	t.Run("open_failure", func(t *testing.T) {
		// The lock file itself cannot be created: its parent component is a
		// regular file, which fails even as root.
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		ran := false
		withEpochFileLock(filepath.Join(blocker, "sub", "ha-boot-epoch"), func() { ran = true })
		if ran {
			t.Fatal("withEpochFileLock ran the critical section UNLOCKED after failing to OPEN the " +
				"lock file — that reinstates the concurrent-resolution race exactly when the " +
				"guard cannot fire")
		}
	})

	t.Run("flock_failure", func(t *testing.T) {
		restore := epochFlock
		epochFlock = func(int, int) error { return unix.ENOLCK }
		t.Cleanup(func() { epochFlock = restore })

		ran := false
		withEpochFileLock(filepath.Join(t.TempDir(), "ha-boot-epoch"), func() { ran = true })
		if ran {
			t.Fatal("withEpochFileLock ran the critical section UNLOCKED after flock() failed — " +
				"an opened-but-unlocked file is not a lock, and this is the branch a filesystem " +
				"that does not support flock actually takes")
		}
	})

	t.Run("lock_available", func(t *testing.T) {
		ran := false
		withEpochFileLock(filepath.Join(t.TempDir(), "ha-boot-epoch"), func() { ran = true })
		if !ran {
			t.Fatal("withEpochFileLock did not run the critical section when the lock was available")
		}
	})
}

// TestEpochForwardSlackIsNotLockoutScale_6169 pins the SIZE of the forward
// bound, because the slack is itself the worst-case lockout.
//
// An epoch INSIDE the bound is latched. A peer that is then repaired and
// returns to real time sits below that floor until its own wall-clock seed
// climbs past it — so the slack and the lockout duration are the same number.
// A year of slack bought nothing over an hour (the bound only has to exceed
// real inter-node clock skew, which is milliseconds under NTP and minutes
// without it) and cost a year-long lockout that needs intervention.
//
// RED-on-revert: widen bootEpochMaxSkew back toward a year.
func TestEpochForwardSlackIsNotLockoutScale_6169(t *testing.T) {
	const maxTolerableLockout = uint64(time.Hour)
	if bootEpochMaxSkew > maxTolerableLockout {
		t.Fatalf("bootEpochMaxSkew = %v; an epoch inside the bound IS latched, so this is also the "+
			"worst-case lockout for a repaired peer. Keep it <= %v.",
			time.Duration(bootEpochMaxSkew), time.Duration(maxTolerableLockout))
	}
	// It must still comfortably exceed real clock skew, or healthy peers are refused.
	if bootEpochMaxSkew < uint64(time.Minute) {
		t.Fatalf("bootEpochMaxSkew = %v is below plausible inter-node clock skew",
			time.Duration(bootEpochMaxSkew))
	}
	// And it still closes the MaxUint64 class by orders of magnitude.
	now := uint64(time.Now().UnixNano())
	if epochOrderable(math.MaxUint64, int64(now)) {
		t.Fatal("MaxUint64 must remain unorderable")
	}
	if !epochOrderable(now+bootEpochMaxSkew/2, int64(now)) {
		t.Fatal("an epoch inside the skew allowance must remain orderable")
	}
	if epochOrderable(now+bootEpochMaxSkew*2, int64(now)) {
		t.Fatal("an epoch beyond the skew allowance must be unorderable")
	}
}

// bootEpochIncarnation drives the LIVE production sequence for one daemon
// incarnation: publish the wall-clock seed synchronously, exactly as
// Manager.heartbeatBootEpoch does, then run the persistence refinement. It
// returns the epoch actually advertised and whether that value reached disk.
//
// These tests previously drove a separate nextBootEpoch that duplicated this
// logic and had ZERO production callers — a green suite exercising
// read-modify-write code that shipped nothing and was free to diverge from the
// live path. Someone would eventually have fixed a bug in it, watched the tests
// pass, and changed nothing. Both halves here are shipped functions.
func bootEpochIncarnation(path string) (epoch uint64, persisted bool) {
	var published atomic.Uint64
	published.Store(bootEpochSeed())
	refineBootEpoch(path, &published, 0)
	epoch = published.Load()
	if data, err := os.ReadFile(path); err == nil {
		if n, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); perr == nil && n == epoch {
			persisted = true
		}
	}
	return epoch, persisted
}

// TestReadErrorDoesNotRegressPersistedEpoch_6169 is the fail-on-revert gate for
// the durable regression a transient read error caused.
//
// A non-ENOENT ReadFile error logged, left prev=0, and fell through to
// WriteFileDurable — durably replacing a possibly HIGHER persisted value with
// this incarnation's wall-clock seed. A peer that had latched the higher value
// then refuses this node indefinitely. It is the exact durable regression
// withEpochFileLock's own rationale says must never happen, and the sibling
// branches already decided the other way: MkdirAllDurable failure returns and
// lock failure skips.
//
// The fault is injected with a SELF-REFERENTIAL SYMLINK, which is the shape
// that actually exercises the branch: ReadFile fails ELOOP (non-ENOENT) while
// the temp-file+rename write would SUCCEED, replacing the link. An earlier
// version of this test used a directory, where the write fails too — so it
// passed for a reason unrelated to the fix and did not red under mutation.
//
// RED-on-revert: delete the `return` after the read-error warning in
// refineBootEpoch.
func TestReadErrorDoesNotRegressPersistedEpoch_6169(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")

	// Self-referential symlink: read fails ELOOP, write would succeed.
	if err := os.Symlink(path, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(path); err == nil || os.IsNotExist(err) {
		t.Skipf("could not induce a non-ENOENT read error on this filesystem: %v", err)
	}

	var published atomic.Uint64
	seed := bootEpochSeed()
	published.Store(seed)
	refineBootEpoch(path, &published, 0)

	// The published epoch is untouched — the wall-clock seed is still valid and
	// still on the wire.
	if got := published.Load(); got != seed {
		t.Fatalf("published epoch changed from %d to %d on a read error", seed, got)
	}
	// And nothing was written over the unknown state: the path is still the
	// symlink, not a regular file holding this incarnation's lower seed.
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("state path disappeared: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("refineBootEpoch OVERWROTE unreadable state; a transient read error must ABORT, " +
			"not durably replace a possibly-higher persisted value with this incarnation's seed")
	}
}
