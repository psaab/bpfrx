// Tests for the non-TTY (`-c`) safety guards added in #1563.
//
// The remote `cli` binary segfaulted when invoked as `cli -c "configure"`
// from a non-TTY context (e.g. `incus exec`, scripted CI) because the
// dispatch path touched the readline instance before it was initialized
// — readline.NewEx() runs AFTER `-c` dispatch in cmd/cli/main.go. The
// `c.rl == nil` guards in these tests pin the safe behavior in place:
//
//   - `configure` returns a hard error rather than issuing the
//     EnterConfigure RPC, which would leak the daemon-side config
//     lock (the gRPC configLockInterceptor is unary-only and never
//     fires on connection close).
//   - The destructive `request system <action>` paths (reboot, halt,
//     power-off, zeroize, in-service-upgrade) return a hard error
//     rather than silently proceeding without operator confirmation.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// fakeBpfrxClient embeds the generated client interface so we can
// override only the RPC methods we care about. Any method the test
// does not override will nil-panic when called — which is exactly
// what we want, since calling an un-stubbed RPC from the test path
// is itself a bug.
type fakeBpfrxClient struct {
	pb.BpfrxServiceClient

	enterConfigureCalls int
	systemActionCalls   int
}

func (f *fakeBpfrxClient) EnterConfigure(
	_ context.Context, _ *pb.EnterConfigureRequest, _ ...grpc.CallOption,
) (*pb.EnterConfigureResponse, error) {
	f.enterConfigureCalls++
	return &pb.EnterConfigureResponse{}, nil
}

func (f *fakeBpfrxClient) SystemAction(
	_ context.Context, _ *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	f.systemActionCalls++
	return &pb.SystemActionResponse{Message: "ok"}, nil
}

// TestDispatchOperational_ConfigureNonTTYHardErrors verifies that
// `cli -c "configure"` returns a hard error and crucially does NOT
// issue the EnterConfigure RPC. Issuing the RPC and then exiting
// would leak the daemon-side config lock (see comments in
// dispatchOperational + pkg/grpcapi/server.go configLockInterceptor).
func TestDispatchOperational_ConfigureNonTTYHardErrors(t *testing.T) {
	fake := &fakeBpfrxClient{}
	c := &ctl{
		client: fake,
		rl:     nil, // non-TTY mode
	}

	err := c.dispatchOperational("configure")
	if err == nil {
		t.Fatal("dispatchOperational(\"configure\") returned nil; expected non-nil error")
	}
	if !strings.Contains(err.Error(), "interactive terminal") {
		t.Errorf("expected error mentioning interactive terminal, got %v", err)
	}

	if fake.enterConfigureCalls != 0 {
		t.Errorf("EnterConfigure RPC was issued %d times; expected 0 (no lock leak)",
			fake.enterConfigureCalls)
	}
	if c.configMode {
		t.Error("c.configMode = true after hard-errored configure; expected false")
	}
}

// TestDispatchOperational_ConfigureExclusiveNonTTYHardErrors covers
// the `cli -c "configure exclusive"` variant — the guard must fire
// before the exclusive-form branches.
func TestDispatchOperational_ConfigureExclusiveNonTTYHardErrors(t *testing.T) {
	fake := &fakeBpfrxClient{}
	c := &ctl{
		client: fake,
		rl:     nil,
	}

	err := c.dispatchOperational("configure exclusive")
	if err == nil {
		t.Fatal("dispatchOperational(\"configure exclusive\") returned nil")
	}
	if fake.enterConfigureCalls != 0 {
		t.Errorf("EnterConfigure issued %d times for `configure exclusive`; expected 0",
			fake.enterConfigureCalls)
	}
}

// TestConfirmYes_NoTTYError pins the helper's non-TTY contract:
// hard-error rather than silently consuming stdin.
func TestConfirmYes_NoTTYError(t *testing.T) {
	c := &ctl{
		client: &fakeBpfrxClient{},
		rl:     nil,
	}

	ok, err := c.confirmYes("Reboot the system? [yes,no] (no) ")
	if err == nil {
		t.Fatal("confirmYes returned nil error in non-TTY mode")
	}
	if !strings.Contains(err.Error(), "interactive confirmation") {
		t.Errorf("expected error mentioning interactive confirmation, got %v", err)
	}
	if ok {
		t.Error("confirmYes returned ok=true in non-TTY mode; expected false")
	}
}

// TestHandleRequestSystem_NonTTYBlocksDestructive verifies that every
// destructive `request system <action>` command refuses to issue the
// SystemAction RPC when there is no interactive terminal. Table-driven
// across every prompt-guarded command per AGY round-3 finding.
func TestHandleRequestSystem_NonTTYBlocksDestructive(t *testing.T) {
	commands := []struct {
		name string
		args []string
	}{
		{"reboot", []string{"system", "reboot"}},
		{"halt", []string{"system", "halt"}},
		{"power-off", []string{"system", "power-off"}},
		{"zeroize", []string{"system", "zeroize"}},
		{"in-service-upgrade",
			[]string{"system", "software", "in-service-upgrade"}},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{
				client: fake,
				rl:     nil,
			}

			err := c.handleRequest(tc.args)
			if err == nil {
				t.Fatalf("handleRequest(%v) returned nil error; expected hard error",
					tc.args)
			}
			if !strings.Contains(err.Error(), "interactive confirmation") {
				t.Errorf("expected error mentioning interactive confirmation, got %v",
					err)
			}
			if fake.systemActionCalls != 0 {
				t.Errorf("SystemAction RPC was issued %d times for %q; "+
					"expected 0 — destructive action must not proceed in non-TTY",
					fake.systemActionCalls, tc.name)
			}
		})
	}
}
