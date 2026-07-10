package grpcapi

import (
	"context"
	"testing"
	"time"
)

// TestClampGRPCBindToLoopback pins the pure decision (#5035): the primary,
// unauthenticated gRPC listener must never bind off-loopback. A wildcard or
// routable bind is pulled back to a same-family loopback; a genuine loopback
// bind is returned unchanged.
func TestClampGRPCBindToLoopback(t *testing.T) {
	cases := []struct {
		addr        string
		wantAddr    string
		wantClamped bool
	}{
		// Off-loopback binds MUST be clamped (the exposure this fixes).
		{"0.0.0.0:50051", "127.0.0.1:50051", true},
		{":50051", "127.0.0.1:50051", true}, // Go wildcard spelling — all interfaces
		{"192.0.2.1:50051", "127.0.0.1:50051", true},
		{"[::]:50051", "[::1]:50051", true},
		{"[2001:db8::1]:50051", "[::1]:50051", true},
		// Genuine loopback binds are left unchanged.
		{"127.0.0.1:50051", "127.0.0.1:50051", false},
		{"127.0.0.53:50051", "127.0.0.53:50051", false},
		{"[::1]:50051", "[::1]:50051", false},
		{"localhost:50051", "localhost:50051", false},
		// No port to clamp — returned unchanged.
		{"not-an-addr", "not-an-addr", false},
	}
	for _, c := range cases {
		gotAddr, gotClamped := clampGRPCBindToLoopback(c.addr)
		if gotAddr != c.wantAddr || gotClamped != c.wantClamped {
			t.Errorf("clampGRPCBindToLoopback(%q) = (%q, %v), want (%q, %v)",
				c.addr, gotAddr, gotClamped, c.wantAddr, c.wantClamped)
		}
	}
}

// TestRunClampsNonLoopbackBind proves the clamp is actually wired into Run
// (#5035): Run is given a routable, host-unassignable TEST-NET-1 address. With
// the clamp, Run rewrites the bind to loopback and keeps serving; without it
// (revert), net.Listen fails to assign 192.0.2.1 and Run returns an error
// almost immediately — which this test detects as an early exit.
func TestRunClampsNonLoopbackBind(t *testing.T) {
	s := &Server{addr: "192.0.2.1:0"} // RFC 5737 TEST-NET-1: never assigned to a host
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	select {
	case err := <-errCh:
		// Run exited before we cancelled the context — it never bound, so the
		// clamp is absent and the non-loopback bind was attempted directly.
		t.Fatalf("Run exited early (bind was not clamped to loopback): %v", err)
	case <-time.After(300 * time.Millisecond):
		// Still serving after the grace window — the bind was clamped to
		// loopback and net.Listen succeeded.
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
