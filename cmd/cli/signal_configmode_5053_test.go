// cli is the remote CLI client for xpfd.
//
// Regression coverage for #5053: the SIGINT goroutine reads c.configMode
// concurrently with the main loop's configure/exit/EOF transitions. Before the
// fix configMode was a plain bool, so the read raced the write (a Go
// memory-model data race) and a Ctrl-C landing during a mode transition could
// observe stale state and SKIP the explicit ExitConfigure cleanup. configMode
// is now an atomic.Bool and every access goes through Load/Store.
package main

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// exitConfigureRecorderClient records ExitConfigure invocations. It embeds the
// generated client so only ExitConfigure is stubbed; any other RPC nil-panics,
// which is what we want from an un-stubbed call on this path.
type exitConfigureRecorderClient struct {
	pb.BpfrxServiceClient
	exitConfigureCalls int32
}

func (f *exitConfigureRecorderClient) ExitConfigure(
	_ context.Context, _ *pb.ExitConfigureRequest, _ ...grpc.CallOption,
) (*pb.ExitConfigureResponse, error) {
	atomic.AddInt32(&f.exitConfigureCalls, 1)
	return &pb.ExitConfigureResponse{}, nil
}

// TestExitOnInterruptConfigModeRace_5053 drives the SIGINT goroutine's
// configMode read (via exitOnInterrupt) concurrently with the main loop's mode
// transitions (Store). With the atomic.Bool fix `go test -race` is clean;
// against the pre-fix plain-bool field the two goroutines race the same word
// and the detector flags it (RED-on-revert).
func TestExitOnInterruptConfigModeRace_5053(t *testing.T) {
	fake := &exitConfigureRecorderClient{}
	c := &ctl{client: fake}
	noExit := func() {}

	const iters = 20000
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: the main loop's configure/exit/EOF transitions flip configMode.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			c.configMode.Store(i%2 == 0)
		}
	}()

	// Reader: the SIGINT double-Ctrl-C teardown reads configMode.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			c.exitOnInterrupt(fake, noExit)
		}
	}()

	wg.Wait()
}

// TestSignalLoopExitConfigureNotSkipped_5053 drives the real signal loop with
// an injected channel: a double Ctrl-C while in configuration mode MUST issue
// exactly one ExitConfigure so the daemon-side config lock is released. A
// stale/racy configMode read on the pre-fix code could observe false here and
// skip the cleanup.
func TestSignalLoopExitConfigureNotSkipped_5053(t *testing.T) {
	fake := &exitConfigureRecorderClient{}
	c := &ctl{client: fake}
	c.configMode.Store(true) // in configuration mode

	sigCh := make(chan os.Signal, 2)
	exited := make(chan struct{})
	onExit := func() { close(exited) }

	go c.runSignalLoop(sigCh, fake, nil, onExit)

	// First interrupt arms the 2s window; the second within it triggers the
	// teardown.
	sigCh <- os.Interrupt
	sigCh <- os.Interrupt

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("signal loop did not reach the exit branch on double Ctrl-C")
	}

	if got := atomic.LoadInt32(&fake.exitConfigureCalls); got != 1 {
		t.Fatalf("ExitConfigure called %d times on double Ctrl-C in config mode; "+
			"want exactly 1 (Ctrl-C cleanup must not be skipped)", got)
	}
}

// TestSignalLoopNoExitConfigureWhenOperational_5053 is the complement: a double
// Ctrl-C in operational mode must NOT issue ExitConfigure (nothing to release),
// proving the configMode gate is honored on the teardown path.
func TestSignalLoopNoExitConfigureWhenOperational_5053(t *testing.T) {
	fake := &exitConfigureRecorderClient{}
	c := &ctl{client: fake}
	// configMode stays false (operational).

	sigCh := make(chan os.Signal, 2)
	exited := make(chan struct{})
	onExit := func() { close(exited) }

	go c.runSignalLoop(sigCh, fake, nil, onExit)

	sigCh <- os.Interrupt
	sigCh <- os.Interrupt

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("signal loop did not reach the exit branch on double Ctrl-C")
	}

	if got := atomic.LoadInt32(&fake.exitConfigureCalls); got != 0 {
		t.Fatalf("ExitConfigure called %d times on double Ctrl-C in operational mode; want 0", got)
	}
}
