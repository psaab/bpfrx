// #7611: the primary (loopback) gRPC listener is supervised, and its faults stay
// LOUD.
//
// Before this a bind or serve fault was terminal — `Run` is called exactly once,
// so the loopback endpoint was gone for the life of the process and every
// gRPC-driven surface with it. #5047 gave the fabric listener a supervisor and
// stopped at one of the two listeners its own comment describes.
//
// The escalation policy is asserted through `primaryListenerEscalations()`
// rather than by matching log output. A log-string assertion would be a probe
// keyed to the message text: it would survive a change that silently downgraded
// Error to Warn as long as the words stayed the same, and it would red on a
// harmless rewording. The counter is the property.
package grpcapi

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	"github.com/psaab/xpf/pkg/sysservices"
)

// primaryTestCfg is the supervisor wired for tests: millisecond backoff so a
// cell finishes fast, and `healthyServe` set by the caller because several cells
// turn on whether a serve session counted as healthy.
func primaryTestCfg(
	listen func(context.Context) (net.Listener, error),
	serve func(context.Context, net.Listener) error,
	healthyServe time.Duration,
) primarySupervisorConfig {
	return primarySupervisorConfig{
		backoffBase:  time.Millisecond,
		backoffMax:   4 * time.Millisecond,
		healthyServe: healthyServe,
		listen:       listen,
		serve:        serve,
	}
}

// A transient bind failure must NOT be terminal: the supervisor retries, binds,
// and reports Listening.
//
// FAIL-ON-REVERT: restore the pre-#7611 `return fmt.Errorf("gRPC listen: %w")`
// and the first failure ends it — the state never reaches Listening.
func TestPrimaryListenerRecoversFromTransientBindFailure7611(t *testing.T) {
	s := &Server{addr: "127.0.0.1:0"}
	const failFirst = 3
	var attempts atomic.Int32
	bound := make(chan struct{})
	var once atomic.Bool

	cfg := primaryTestCfg(
		func(context.Context) (net.Listener, error) {
			if n := attempts.Add(1); n <= failFirst {
				return nil, fmt.Errorf("transient bind failure %d", n)
			}
			return bufconn.Listen(1 << 20), nil
		},
		func(ctx context.Context, lis net.Listener) error {
			if once.CompareAndSwap(false, true) {
				close(bound)
			}
			<-ctx.Done()
			return nil
		},
		time.Hour,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.supervisePrimaryListener(ctx, cfg); close(done) }()

	select {
	case <-bound:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor never bound: a transient bind failure is still terminal (#7611)")
	}
	if got := attempts.Load(); got <= failFirst {
		t.Fatalf("listen attempts = %d, want > %d — the supervisor must retry past the transient failures", got, failFirst)
	}
	if got := s.EffectiveListener().State; got != sysservices.StateListening {
		t.Errorf("EffectiveListener().State = %v after a successful re-bind, want StateListening — "+
			"the state must track reality across retries rather than latching at Failed (#6401)", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not return after ctx cancel")
	}
}

// The escalation policy, which is the part that keeps this from being a
// visibility REGRESSION.
//
// The primary listener's state reaches only `sysservices.Listeners` — the
// console CLI in-process, and `show system services` over the gRPC that is
// down. It is on neither REST nor Prometheus (#8195). Today a fault is logged
// exactly once at Error; a supervisor that mirrored the fabric listener's
// levels verbatim (Warn per fault, Debug per tick) would make a PERMANENT bind
// failure quieter than the code it replaced.
//
// So: Error on the first fault of a run, Error again once the backoff reaches
// its cap, Warn in between.
//
// FAIL-ON-REVERT: drop the `atCap && !*escalatedAtCap` arm and the cap
// escalation never fires — this reds at exactly 1.
func TestPrimaryListenerEscalatesFirstFaultAndAgainAtBackoffCap7611(t *testing.T) {
	s := &Server{addr: "127.0.0.1:0"}
	var attempts atomic.Int32

	cfg := primaryTestCfg(
		func(context.Context) (net.Listener, error) {
			attempts.Add(1)
			return nil, fmt.Errorf("permanent bind failure")
		},
		func(context.Context, net.Listener) error { return nil },
		time.Hour,
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervisePrimaryListener(ctx, cfg); close(done) }()

	// Wait for the backoff to have grown past its cap (base 1ms doubling to a
	// 4ms cap), plus margin.
	deadline := time.Now().Add(5 * time.Second)
	for s.primaryListenerEscalations() < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done

	got := s.primaryListenerEscalations()
	if got < 2 {
		t.Errorf("primaryListenerEscalations() = %d after a persistent bind failure, want >= 2: "+
			"the first fault must be ERROR and the fault must escalate again once the backoff "+
			"reaches its cap. Without the second, a permanent failure decays into Warn/Debug and "+
			"becomes QUIETER than the pre-#7611 single Error — while the issue reads as fixed "+
			"(#7611, #8195)", got)
	}
	// And it must not escalate on EVERY fault, or the level carries no
	// information and an operator learns to filter it.
	if att := attempts.Load(); att > 4 && got >= uint64(att) {
		t.Errorf("primaryListenerEscalations() = %d for %d attempts — every fault escalated, so "+
			"ERROR no longer distinguishes 'first/persistent' from 'retrying', which is the "+
			"whole point of the policy", got, att)
	}
}

// A serve session that stayed up longer than healthyServe resets the run, so a
// listener that recovers and later faults again is LOUD again rather than
// inheriting the previous run's decayed level.
//
// Without the reset a long-lived daemon's second outage — months later, and just
// as serious — would be reported at Warn because the counter never went back.
func TestPrimaryListenerHealthyServeResetsEscalation7611(t *testing.T) {
	s := &Server{addr: "127.0.0.1:0"}
	var serves atomic.Int32

	cfg := primaryTestCfg(
		func(context.Context) (net.Listener, error) { return bufconn.Listen(1 << 20), nil },
		func(ctx context.Context, lis net.Listener) error {
			// Every serve session faults immediately, but healthyServe is 0 so
			// each counts as healthy — which is what resets the run.
			serves.Add(1)
			return fmt.Errorf("serve fault")
		},
		0,
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervisePrimaryListener(ctx, cfg); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for serves.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	n := serves.Load()
	if n < 3 {
		t.Fatalf("only %d serve sessions ran; the cell needs at least 3 to observe the reset", n)
	}
	// Each session counted as healthy, so each fault is the first of its run
	// and escalates.
	if got := s.primaryListenerEscalations(); got < uint64(n)-1 {
		t.Errorf("primaryListenerEscalations() = %d over %d healthy-then-faulting sessions, want ~%d: "+
			"a serve session that stayed up must reset the run, or a recovered listener's next "+
			"outage is reported at the previous run's decayed level (#7611)", got, n, n-1)
	}
}
