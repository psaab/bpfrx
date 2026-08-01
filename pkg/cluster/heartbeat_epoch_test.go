package cluster

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// #6169: an on-link attacker holding heartbeatReplaySessions+1 or more captured
// authenticated peer incarnations can churn the bounded session ring by REPLAY
// ALONE and sustain forged peer liveness indefinitely. The signed boot epoch
// gives the receiver a total order over incarnations and closes it.
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

func newEpochEnv(t *testing.T) *epochEnv {
	t.Helper()
	m := NewManager(0, 42)
	e := &epochEnv{t: t, m: m, key: []byte("cluster-shared-secret")}
	e.restartHeartbeat()
	return e
}

// restartHeartbeat models what StartHeartbeat/RestartHeartbeat do to the
// receiver: drop the old one and install a brand-new one from
// newHeartbeatReceiver. No sockets or goroutines; the read path is driven
// directly.
func (e *epochEnv) restartHeartbeat() {
	e.t.Helper()
	e.r = newHeartbeatReceiver(e.m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval)
	e.r.startedAt = time.Now().Add(-2 * heartbeatStartupGrace)
	e.m.mu.Lock()
	e.m.hbReceiver = e.r
	e.m.mu.Unlock()
}

// feed pushes one raw frame through the EXACT gate readLoop applies (see
// heartbeatReceiver.readLoop) and applies the exact consequences readLoop
// applies on accept. It reports whether the frame was accepted.
func (e *epochEnv) feed(frame []byte) bool {
	e.t.Helper()
	pkt, err := UnmarshalHeartbeat(frame)
	if err != nil {
		e.t.Fatalf("unmarshal: %v", err)
	}
	session, counter, present := heartbeatAuthTrailer(frame)
	macOK := present && len(e.key) > 0 && verifyHeartbeatMAC(frame, e.key)
	var (
		epoch    uint64
		hasEpoch bool
	)
	if macOK {
		epoch, hasEpoch = heartbeatFrameEpoch(frame, e.key)
	}
	nonceFresh := macOK && e.r.auth.admitAuthed(hasEpoch, epoch, session, counter)
	accept, _ := heartbeatAuthDecision(len(e.key) > 0, present, macOK, nonceFresh, e.r.auth.peerAuthenticated())
	if !accept {
		return false
	}
	if macOK {
		e.r.auth.notePeerAuthenticated()
	}
	e.r.lastSeen.Store(MonotonicNanos())
	e.m.handlePeerHeartbeat(pkt)
	return true
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
	// incarnation now signs its own strictly-increasing boot epoch. Once the
	// receiver has seen the newest incarnation, every captured retired one is
	// below the floor and is rejected before it can touch the ring.
	t.Run("epoch_rejects_every_retired_incarnation", func(t *testing.T) {
		e := newEpochEnv(t)
		const n = heartbeatReplaySessions + 8 // comfortably past the churn threshold
		caps := make([][][]byte, 0, n)
		for i := 0; i < n; i++ {
			// A real daemon restart draws a fresh session AND a strictly higher
			// epoch (nextBootEpoch).
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
func TestNextBootEpochMonotonic_6169(t *testing.T) {
	// First boot with no persisted value seeds from the wall clock, well above
	// any low retired counter, and persists.
	t.Run("first_boot_seeds_from_wall_clock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sub", "ha-boot-epoch")
		before := uint64(time.Now().UnixNano())
		got, ok := nextBootEpoch(path)
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

	// Restarts are STRICTLY increasing, including back-to-back ones. The
	// wall-clock term is nanosecond-resolution so it is already unique across a
	// process restart; a coarser seed would hand two incarnations starting in
	// the same interval identical values.
	t.Run("restarts_strictly_increase", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		prev := uint64(0)
		for i := 0; i < 200; i++ {
			got, ok := nextBootEpoch(path)
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
		got, ok := nextBootEpoch(path)
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
	// That is the right way round. Such a value is only reachable if this
	// node's own clock was the wrong one when it persisted — and in that case
	// the peer (with a correct clock) refused and never latched it, so nothing
	// is locked out. Chaining from it instead would strand this node
	// permanently above the range its peer will ever accept, with no way back
	// down. Recoverable regression beats unrecoverable lockout.
	t.Run("value_beyond_the_forward_bound_is_not_chained_from", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha-boot-epoch")
		farAhead := uint64(time.Now().UnixNano()) + bootEpochMaxSkew*3
		if err := os.WriteFile(path, []byte(strconv.FormatUint(farAhead, 10)), 0o644); err != nil {
			t.Fatal(err)
		}
		got, ok := nextBootEpoch(path)
		if !ok {
			t.Fatal("persist failed")
		}
		if got >= farAhead {
			t.Fatalf("epoch = %d, chained from an out-of-range persisted value %d — "+
				"this node could never come back down into its peer's accepted range", got, farAhead)
		}
		if !epochOrderable(got, time.Now().UnixNano()) {
			t.Fatalf("reseeded epoch %d is itself out of range", got)
		}
		// The file was healed, so the next boot chains normally.
		if next, _ := nextBootEpoch(path); next <= got {
			t.Fatalf("after healing, the next epoch %d did not exceed %d", next, got)
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
		got, ok := nextBootEpoch(path)
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
		got, persisted := nextBootEpoch(filepath.Join(blocker, "sub", "ha-boot-epoch"))
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
		first, ok1 := nextBootEpoch(path)
		second, ok2 := nextBootEpoch(path)
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

// TestHeartbeatBootEpochResolvesAsync_6169 pins that the epoch is resolved off
// the send path. Resolution fsyncs; doing it inline would block the 100ms send
// loop on a wedged disk and cause the very failover the mechanism protects
// against. Until it resolves, the sender advertises no epoch (0).
func TestHeartbeatBootEpochResolvesAsync_6169(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha-boot-epoch")
	orig := bootEpochPath
	bootEpochPath = path
	t.Cleanup(func() { bootEpochPath = orig })

	m := NewManager(0, 42)
	m.heartbeatBootEpoch() // kicks the async resolve
	deadline := time.Now().Add(5 * time.Second)
	var got uint64
	for time.Now().Before(deadline) {
		if got = m.heartbeatBootEpoch(); got != 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got == 0 {
		t.Fatal("boot epoch never resolved")
	}
	// Stable across calls — one epoch per daemon incarnation.
	for i := 0; i < 10; i++ {
		if again := m.heartbeatBootEpoch(); again != got {
			t.Fatalf("boot epoch changed within one incarnation: %d then %d", got, again)
		}
	}
}
