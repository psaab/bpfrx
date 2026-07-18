package userspace

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestEventStreamUndecodableSessionFrameForcesResync_5483 pins the #5483 fix: a
// COMPLETE but semantically undecodable SESSION frame (open/close/update) must
// force the same hard sync-break a #2874 sequence gap forces — it must NOT be
// silently skipped, and the cumulative ACK must NOT advance past its sequence.
//
// The divergence the fix closes (pre-#5483 behaviour):
//   - seq 1  session open (decodes OK)        -> applied, watermark = 1
//   - seq 2  session open, UNDECODABLE        -> `DecodeErrors.Add(1); continue`
//                                                skipped it, leaving prevSeq=1
//   - seq 3  telemetry frame (decodes OK)     -> only records a benign gap,
//                                                marks itself applied, advancing
//                                                lastAppliedSeq to 3
//     sendAckIfNeeded then ACKs seq 3, the Rust replay buffer trims through 3
//     (INCLUDING the never-applied session frame 2), and no later gap fires ->
//     the standby has silently diverged with no recovery.
//
// With the fix, seq 2 routes through handleSessionDecodeFailure: SessionSyncResyncs
// is bumped, onFullResync fires, and the reader returns (drops the connection)
// WITHOUT advancing the watermark. The queued telemetry frame at seq 3 is never
// read, so lastAppliedSeq stays at 1 and the ACK never moves past the hole.
//
// Fail-on-revert (target-count 1): restore the EventTypeSessionOpen decode-failure
// arm to `es.DecodeErrors.Add(1); continue`. Then seq 2 is skipped, seq 3 is
// dispatched and advances lastAppliedSeq to 3, onFullResync is never called, and
// SessionSyncResyncs stays 0 — turning the resync/onFullResync/watermark
// assertions RED.
func TestEventStreamUndecodableSessionFrameForcesResync_5483(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })
	// A telemetry consumer so a surviving seq-3 telemetry frame (the reverted
	// path) is actually dispatched and advances the watermark.
	es.SetOnRawDataplaneEvent(func(uint64, []byte) {})
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	sessionPayload := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	// Establish a contiguous baseline at seq 1 and wait for it to be applied so
	// the ACK watermark is anchored at 1.
	if err := writeFrame(conn, EventTypeSessionOpen, 1, sessionPayload); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	dl = time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() != 1 {
		if time.Now().After(dl) {
			t.Fatalf("seq 1 not applied; lastApplied=%d", es.lastAppliedSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// seq 2: a COMPLETE session-open frame (full 64-byte payload, fully read off
	// the wire) whose content the typed decoder rejects — an invalid address
	// family makes decodeSessionEvent return ok=false. This is "present but
	// undecodable", NOT a truncated-on-wire frame.
	undecodable := append([]byte(nil), sessionPayload...)
	undecodable[0] = 7 // invalid AddrFamily (valid values are 4/6) -> decode fails
	if err := writeFrame(conn, EventTypeSessionOpen, 2, undecodable); err != nil {
		t.Fatalf("write seq 2 (undecodable): %v", err)
	}

	// seq 3: a valid telemetry frame queued immediately behind the undecodable
	// session frame. In the reverted (buggy) path this is read on the still-open
	// connection and advances lastAppliedSeq to 3 — the ACK-past-the-hole that
	// silently diverges the standby. In the fixed path the connection has already
	// been dropped, so this frame is never read. The write may error (broken
	// pipe) once the server closes its side — that is expected; ignore it.
	telemetryPayload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)
	_ = writeFrame(conn, EventFrameTypePolicyDeny, 3, telemetryPayload)

	// Terminal condition: EITHER the fix forced a resync, OR the buggy path let
	// the watermark advance past the hole. Whichever happens, stop waiting.
	dl = time.Now().Add(2 * time.Second)
	for !resyncCalled.Load() && es.lastAppliedSeq.Load() < 3 {
		if time.Now().After(dl) {
			t.Fatal("neither resync fired nor watermark advanced within timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Small settle so a mistakenly-dispatched seq 3 has fully advanced the
	// watermark before we assert (guards against reading mid-dispatch).
	time.Sleep(50 * time.Millisecond)

	if !resyncCalled.Load() {
		t.Fatal("undecodable session frame did not trigger onFullResync (#5483): " +
			"it was silently skipped instead of forcing a hard sync-break")
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1 (an undecodable session frame "+
			"must force exactly one resync, like a #2874 gap)", got)
	}
	// CORE #5483 invariant: the cumulative ACK/applied watermark must NOT have
	// advanced past the undecodable session seq (2). It must stay anchored at the
	// last contiguous sequence (1); a later telemetry frame must not be able to
	// carry it to 3.
	if applied := es.lastAppliedSeq.Load(); applied > 1 {
		t.Fatalf("lastAppliedSeq advanced past the undecodable session frame: "+
			"got %d, want 1 — the ACK moved past unapplied session state, which "+
			"lets the Rust replay buffer trim it and silently diverge the standby (#5483)", applied)
	}
	if acked := es.lastAckSeq.Load(); acked > 1 {
		t.Fatalf("ACK advanced past the undecodable session frame: lastAckSeq=%d, want <=1", acked)
	}
	// The decode failure is still accounted as a decode error.
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
}

// TestEventStreamUndecodableTelemetryFrameStillSkips_5483 pins the SCOPE of the
// #5483 fix: the hard sync-break applies to SESSION frames ONLY. A COMPLETE but
// undecodable TELEMETRY (RT_FLOW) frame stays tolerable to skip — it carries no
// HA session state, so it must NOT force a resync. The reader accounts it
// (DecodeErrors + drop counter), advances the watermark past it
// (markDroppedFrameApplied), and keeps the connection alive.
//
// Fail-on-revert guard: if the session hard-break policy were mistakenly widened
// to telemetry frames, onFullResync would fire and the following telemetry frame
// would not be dispatched.
func TestEventStreamUndecodableTelemetryFrameStillSkips_5483(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	gotSeqs := make(chan uint64, 4)
	es.SetOnRawDataplaneEvent(func(seq uint64, _ []byte) { gotSeqs <- seq })
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	goodTelemetry := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)

	// seq 1: an undecodable telemetry frame (too short to match the frame's
	// event-type gate) — skipped, watermark advanced.
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 1, []byte{4, 6}); err != nil {
		t.Fatalf("write seq 1 (undecodable telemetry): %v", err)
	}
	// seq 2: a valid telemetry frame that must still be dispatched over the
	// still-alive connection.
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 2, goodTelemetry); err != nil {
		t.Fatalf("write seq 2: %v", err)
	}

	select {
	case s := <-gotSeqs:
		if s != 2 {
			t.Fatalf("dispatched telemetry seq = %d, want 2", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid telemetry frame after an undecodable telemetry frame was not dispatched")
	}

	if resyncCalled.Load() {
		t.Fatal("an undecodable TELEMETRY frame must NOT force a resync (#5483 scope: session frames only)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 0 {
		t.Fatalf("SessionSyncResyncs = %d, want 0 for an undecodable telemetry frame", got)
	}
}
