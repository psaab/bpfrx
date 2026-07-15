package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// #5807: xpfd must capture SIGTERM / (daemon-mode) SIGINT BEFORE the mutating
// startup phases so a signal mid-startup aborts the remaining phases and runs
// the ordered teardown, instead of the process default-terminating with
// partially-applied links / routes / FRR / dataplane state.

// TestStartupSignalContextCancellableChild5807 pins that the context Run threads
// into the startup phases is a CANCELLABLE child of its parent — not
// context.Background(), whose Done() channel is nil so no cancellation (signal
// or otherwise) can ever be observed by the startup phases.
//
// RED on revert: a revert that hands the mutating phases context.Background()
// (the pre-#5807 shape, where NotifyContext was installed only AFTER the phases)
// returns a context whose Done() is nil — the first assertion fails.
func TestStartupSignalContextCancellableChild5807(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	ctx, stop := startupSignalContext(parent)
	defer stop()

	if ctx.Done() == nil {
		t.Fatal("startupSignalContext must return a CANCELLABLE context (Done() != nil), not context.Background()")
	}
	// It must be a child of parent: cancelling the parent cancels it. This is
	// what lets a caller-driven shutdown (or the OS signal) reach startup.
	cancelParent()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("startupSignalContext result did not cancel when its parent was cancelled")
	}
}

// TestRunStartupPhasesAbortsOnSignal5807 pins that a cancellation observed
// mid-startup stops the sequence at the next phase boundary: the remaining
// phases (and their mutations) do NOT run, and every phase receives the
// cancellable signal context.
//
// RED on revert: removing the per-phase ctx.Err() check in runStartupPhases
// lets phase p3/p4 run after p2 cancelled — the "later phases must not run"
// assertion fails.
func TestRunStartupPhasesAbortsOnSignal5807(t *testing.T) {
	d := &Daemon{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ran []string
	phase := func(name string, cancelHere bool) startupPhase {
		return startupPhase{name: name, run: func(pctx context.Context) error {
			ran = append(ran, name)
			// Each phase must observe the cancellable signal context — a
			// non-cancellable (Background) ctx would make startup un-abortable.
			if pctx.Done() == nil {
				t.Errorf("phase %q received a non-cancellable ctx (Background regression #5807)", name)
			}
			if cancelHere {
				cancel() // simulate a SIGTERM landing during phase p2
			}
			return nil
		}}
	}
	phases := []startupPhase{
		phase("p1", false),
		phase("p2", true),
		phase("p3", false),
		phase("p4", false),
	}

	err := d.runStartupPhases(ctx, phases)
	if err == nil {
		t.Fatal("runStartupPhases must return a non-nil error when a signal cancels startup")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("abort error must wrap context.Canceled, got %v", err)
	}
	if got := strings.Join(ran, ","); got != "p1,p2" {
		t.Fatalf("phases after the cancellation must NOT run; ran=%q want %q", got, "p1,p2")
	}
}

// TestRunStartupPhasesCleanRun5807 pins the happy path: with no cancellation
// every phase runs in order and the result is nil.
func TestRunStartupPhasesCleanRun5807(t *testing.T) {
	d := &Daemon{}
	var ran []string
	phases := []startupPhase{
		{"a", func(context.Context) error { ran = append(ran, "a"); return nil }},
		{"b", func(context.Context) error { ran = append(ran, "b"); return nil }},
		{"c", func(context.Context) error { ran = append(ran, "c"); return nil }},
	}
	if err := d.runStartupPhases(context.Background(), phases); err != nil {
		t.Fatalf("clean startup returned %v, want nil", err)
	}
	if got := strings.Join(ran, ","); got != "a,b,c" {
		t.Fatalf("phases ran %q, want a,b,c", got)
	}
}

// TestRunStartupOrAbortRunsTeardownOnSignal5807 pins the whole observable
// contract: a signal cancelling startup mid-phase (a) aborts the remaining
// phases and (b) invokes the teardown/cleanup path for the initialized subset,
// with the abort error threaded to it. The teardown is injected so the wiring is
// asserted without running the real subsystem teardown.
//
// RED on revert: making runStartupOrAbort NOT run teardown on a signal abort
// (or reverting runStartupPhases so p3 runs) trips the assertions.
func TestRunStartupOrAbortRunsTeardownOnSignal5807(t *testing.T) {
	d := &Daemon{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ran []string
	phases := []startupPhase{
		{"p1", func(context.Context) error { ran = append(ran, "p1"); return nil }},
		{"p2", func(context.Context) error { ran = append(ran, "p2"); cancel(); return nil }},
		{"p3", func(context.Context) error { ran = append(ran, "p3"); return nil }},
	}

	var teardownErr error
	teardownCalled := false
	err := d.runStartupOrAbort(ctx, phases, func(e error) error {
		teardownCalled = true
		teardownErr = e
		return e
	})

	if err == nil {
		t.Fatal("runStartupOrAbort must return a non-nil error when a signal aborts startup")
	}
	if !teardownCalled {
		t.Fatal("the ordered teardown/cleanup MUST run when a signal aborts startup mid-phase")
	}
	if teardownErr == nil || !errors.Is(teardownErr, context.Canceled) {
		t.Fatalf("teardown must receive the (context-cancelled) abort error, got %v", teardownErr)
	}
	if got := strings.Join(ran, ","); got != "p1,p2" {
		t.Fatalf("phases after the cancellation must NOT run; ran=%q want %q", got, "p1,p2")
	}
}

// TestRunStartupOrAbortPlainErrorNoTeardown5807 pins the boundary: a PLAIN phase
// error (no signal, ctx not cancelled) is returned as-is WITHOUT running the
// ordered teardown — preserving the pre-#5807 early-error path (Run's deferred
// #5308 loop stops are the intended cleanup there). The distinguisher is the
// signal context's state, never the error's identity.
func TestRunStartupOrAbortPlainErrorNoTeardown5807(t *testing.T) {
	d := &Daemon{}
	sentinel := errors.New("manager init failed")
	teardownCalled := false
	phases := []startupPhase{
		{"p1", func(context.Context) error { return nil }},
		{"p2", func(context.Context) error { return sentinel }},
		{"p3", func(context.Context) error { t.Fatal("phase after a failing phase must not run"); return nil }},
	}
	// context.Background() is never cancelled, so this models a plain phase error.
	err := d.runStartupOrAbort(context.Background(), phases, func(error) error {
		teardownCalled = true
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("runStartupOrAbort must return the plain phase error, got %v", err)
	}
	if teardownCalled {
		t.Fatal("a plain phase error (no signal) must NOT trigger the #5807 ordered teardown")
	}
}
