package grpcapi

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakePingStream is a minimal grpc.ServerStreamingServer[pb.PingResponse]
// carrying a context; Send is a no-op (the fake diagnostic never emits).
type fakePingStream struct{ ctx context.Context }

func (f *fakePingStream) Send(*pb.PingResponse) error  { return nil }
func (f *fakePingStream) Context() context.Context     { return f.ctx }
func (f *fakePingStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakePingStream) SendHeader(metadata.MD) error { return nil }
func (f *fakePingStream) SetTrailer(metadata.MD)       {}
func (f *fakePingStream) SendMsg(any) error            { return nil }
func (f *fakePingStream) RecvMsg(any) error            { return nil }

// fakeTracerouteStream mirrors fakePingStream for the Traceroute RPC.
type fakeTracerouteStream struct{ ctx context.Context }

func (f *fakeTracerouteStream) Send(*pb.TracerouteResponse) error { return nil }
func (f *fakeTracerouteStream) Context() context.Context          { return f.ctx }
func (f *fakeTracerouteStream) SetHeader(metadata.MD) error       { return nil }
func (f *fakeTracerouteStream) SendHeader(metadata.MD) error      { return nil }
func (f *fakeTracerouteStream) SetTrailer(metadata.MD)            {}
func (f *fakeTracerouteStream) SendMsg(any) error                 { return nil }
func (f *fakeTracerouteStream) RecvMsg(any) error                 { return nil }

// TestDiagConcurrencyLimitGRPC is the #5057 fail-on-revert guard for the
// gRPC Ping/Traceroute RPCs. It swaps the shared diagLimiter for a fresh
// small-capacity limiter and injects a fake slow diagnostic via the
// streamDiag seam, then fires cap+excess concurrent Ping RPCs. It
// asserts:
//   - at most `cap` RPCs run the diagnostic concurrently,
//   - the `excess` RPCs are rejected immediately with
//     codes.ResourceExhausted (not queued, not hung, not admitted),
//   - after the admitted diagnostics finish the limiter is fully
//     released, so a subsequent RPC succeeds.
//
// RED-on-revert: remove the diagLimiter.Acquire()/ResourceExhausted
// branch from the handlers and every RPC is admitted — rejected drops to
// 0 and the max-concurrency assertion fires.
func TestDiagConcurrencyLimitGRPC(t *testing.T) {
	const (
		capN   = 2
		excess = 5
		total  = capN + excess
	)

	origLimiter := diagLimiter
	origStream := streamDiag
	t.Cleanup(func() { diagLimiter = origLimiter; streamDiag = origStream })
	diagLimiter = diagcmd.NewLimiter(capN)

	var (
		inFlight    int32
		maxObserved int32
		attempts    int32
	)
	gate := make(chan struct{})
	allAttempted := make(chan struct{})
	var once sync.Once
	noteAttempt := func() {
		if atomic.AddInt32(&attempts, 1) == total {
			once.Do(func() { close(allAttempted) })
		}
	}

	streamDiag = func(ctx context.Context, timeout time.Duration, cmd []string, sendFn func(string) error) error {
		cur := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			m := atomic.LoadInt32(&maxObserved)
			if cur <= m || atomic.CompareAndSwapInt32(&maxObserved, m, cur) {
				break
			}
		}
		noteAttempt() // admitted: reached the diagnostic, now holding a slot
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}

	s := &Server{}
	fire := func() error {
		return s.Ping(&pb.PingRequest{Target: "192.0.2.1"},
			&fakePingStream{ctx: context.Background()})
	}

	errs := make([]error, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			e := fire()
			if status.Code(e) == codes.ResourceExhausted {
				noteAttempt() // rejected: fail-fast, counts as an attempt
			}
			errs[idx] = e
		}(i)
	}

	// Hold the gate until every RPC has attempted Acquire, so no admitted
	// RPC frees its slot before the excess have been rejected.
	select {
	case <-allAttempted:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %d attempts; inFlight=%d attempts=%d",
			total, atomic.LoadInt32(&inFlight), atomic.LoadInt32(&attempts))
	}
	close(gate)
	wg.Wait()

	var ok, exhausted, other int
	for _, e := range errs {
		switch {
		case e == nil:
			ok++
		case status.Code(e) == codes.ResourceExhausted:
			exhausted++
		default:
			other++
		}
	}
	if other != 0 {
		t.Fatalf("unexpected RPC errors present: %v", errs)
	}
	if exhausted != excess {
		t.Fatalf("ResourceExhausted count = %d, want %d (excess must be rejected): %v",
			exhausted, excess, errs)
	}
	if ok != capN {
		t.Fatalf("success count = %d, want %d: %v", ok, capN, errs)
	}
	if m := atomic.LoadInt32(&maxObserved); m > capN {
		t.Fatalf("max concurrent diagnostics = %d, want <= %d", m, capN)
	}

	if diagLimiter.InFlight() != 0 {
		t.Fatalf("InFlight after drain = %d, want 0", diagLimiter.InFlight())
	}
	if err := fire(); err != nil {
		t.Fatalf("post-drain Ping failed: %v (limiter not released)", err)
	}
}

// TestDiagConcurrencyLimitGRPCSharedAcrossPingTraceroute proves the gRPC
// Ping and Traceroute RPCs draw from the SAME limiter.
func TestDiagConcurrencyLimitGRPCSharedAcrossPingTraceroute(t *testing.T) {
	origLimiter := diagLimiter
	origStream := streamDiag
	t.Cleanup(func() { diagLimiter = origLimiter; streamDiag = origStream })
	diagLimiter = diagcmd.NewLimiter(1)

	entered := make(chan struct{})
	gate := make(chan struct{})
	streamDiag = func(ctx context.Context, timeout time.Duration, cmd []string, sendFn func(string) error) error {
		close(entered)
		<-gate
		return nil
	}

	s := &Server{}
	done := make(chan error, 1)
	go func() {
		done <- s.Ping(&pb.PingRequest{Target: "192.0.2.1"},
			&fakePingStream{ctx: context.Background()})
	}()
	<-entered

	err := s.Traceroute(&pb.TracerouteRequest{Target: "192.0.2.1"},
		&fakeTracerouteStream{ctx: context.Background()})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("concurrent Traceroute code = %v, want ResourceExhausted (shared limiter)", status.Code(err))
	}

	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}
