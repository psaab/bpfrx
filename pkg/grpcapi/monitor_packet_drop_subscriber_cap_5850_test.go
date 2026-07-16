package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #5850: MonitorPacketDrop is a request-created stream on the loopback-but-
// UNAUTHENTICATED gRPC listener. It used the UNCAPPED EventBuffer.Subscribe, so
// any local process could open an unbounded number of packet-drop streams —
// each adding a buffered channel AND expanding the synchronous O(N) per-event
// fan-out — exhausting memory + event-production CPU. The fix routes it through
// the cap-enforcing TrySubscribe (like the REST SSE surface, #4484 L-2) and
// rejects an over-cap stream with codes.ResourceExhausted.

// fillEventBufToCap subscribes via the capped TrySubscribe until the buffer
// rejects, leaving it exactly AT its subscriber cap and returning the live
// subscriptions (the caller closes them).
func fillEventBufToCap(t *testing.T, eb *logging.EventBuffer) []*logging.Subscription {
	t.Helper()
	var subs []*logging.Subscription
	for i := 0; i < 100000; i++ {
		s := eb.TrySubscribe(1)
		if s == nil {
			return subs
		}
		subs = append(subs, s)
	}
	t.Fatal("event buffer never reached its subscriber cap")
	return nil
}

func waitUntil5850(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestMonitorPacketDropRejectsOverCap_5850 pins the #5850 admission cap: with the
// EventBuffer already at its subscriber cap, a further MonitorPacketDrop RPC must
// be REJECTED with ResourceExhausted rather than admitted (which would bypass the
// cap → unbounded fan-out DoS).
//
// FAIL-ON-REVERT: swapping back to the uncapped Subscribe admits the over-cap
// stream — it enters the stream loop and the bounded context returns
// DeadlineExceeded, NOT ResourceExhausted — so this assertion fires RED.
func TestMonitorPacketDropRejectsOverCap_5850(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	subs := fillEventBufToCap(t, eb)
	defer func() {
		for _, s := range subs {
			s.Close()
		}
	}()
	if len(subs) == 0 {
		t.Fatal("expected the buffer to admit at least one subscriber before the cap")
	}

	s := &Server{store: packetDropTestStore(t), eventBuf: eb}
	// Bounded context so a fail-on-revert (admitted → enters the stream loop)
	// returns a fast DeadlineExceeded instead of hanging; with the cap the RPC
	// returns ResourceExhausted BEFORE it ever subscribes, so the timeout is
	// never reached.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{Node: "local"}, &mockPacketDropStream{ctx: ctx})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over-cap MonitorPacketDrop code = %v, want ResourceExhausted "+
			"(the unauthenticated gRPC stream bypassed the subscriber cap → unbounded fan-out DoS); err=%v",
			status.Code(err), err)
	}
}

// TestMonitorPacketDropTeardownFreesSlot_5850 proves MonitorPacketDrop's
// `defer sub.Close()` unsubscribes on stream teardown, freeing its cap slot: an
// admitted stream holds a slot (a probe TrySubscribe fails at cap), and once its
// context is cancelled the slot is released (the probe then succeeds).
func TestMonitorPacketDropTeardownFreesSlot_5850(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	subs := fillEventBufToCap(t, eb)
	defer func() {
		for _, s := range subs {
			s.Close()
		}
	}()
	if len(subs) == 0 {
		t.Fatal("cap must be >= 1")
	}
	// Free exactly one slot so the MonitorPacketDrop stream can take it.
	subs[len(subs)-1].Close()
	subs = subs[:len(subs)-1]

	s := &Server{store: packetDropTestStore(t), eventBuf: eb}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{Node: "local"}, &mockPacketDropStream{ctx: ctx})
	}()

	// Wait until the stream has taken the last slot: a probe TrySubscribe fails.
	if !waitUntil5850(2*time.Second, func() bool {
		p := eb.TrySubscribe(1)
		if p == nil {
			return true // at cap → the stream holds its slot
		}
		p.Close() // not full yet — release the probe and keep waiting
		return false
	}) {
		cancel()
		<-errc
		t.Fatal("MonitorPacketDrop never took a subscriber slot")
	}

	// Tear the stream down; its defer sub.Close() must free the slot.
	cancel()
	if err := <-errc; err != context.Canceled {
		t.Fatalf("MonitorPacketDrop teardown err = %v, want context.Canceled", err)
	}
	p := eb.TrySubscribe(1)
	if p == nil {
		t.Fatal("subscriber slot NOT freed after MonitorPacketDrop teardown (defer Close did not unsubscribe)")
	}
	p.Close()
}
