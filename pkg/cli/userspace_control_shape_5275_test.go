package cli

import (
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5275 PR2 — pin the shape of cliUserspaceControlProvider.
//
// WHY THIS TEST EXISTS. userspaceDataplaneControl() reaches the forwarding
// mutators by type-asserting c.dp — the handle the CLI was CONSTRUCTED with —
// against this package-private interface, at RUNTIME. That is different from
// cliDataPlane, whose drift is caught at the cli.New(...) assignment site: here
// there is no assignment, so a handle that does not satisfy this interface
// compiles perfectly and the command merely reports "userspace dataplane
// control unavailable" at runtime.
//
// #5275 hands the CLI a facade (pkg/daemon) instead of the raw backend, and the
// daemon carries its own mirror of this interface plus a compile-time assertion
// that the facade satisfies it. That protects the DAEMON side. This test
// protects THIS side: if a method is added to or changed on the interface below,
// the fake stops satisfying it and this file fails to compile — a loud, local
// signal to update the daemon mirror, instead of a CLI command that silently
// stops working on the next boot.
type fakeUserspaceControl5275 struct{}

func (fakeUserspaceControl5275) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}
func (fakeUserspaceControl5275) SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}
func (fakeUserspaceControl5275) SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}
func (fakeUserspaceControl5275) SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}
func (fakeUserspaceControl5275) InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}

// Compile-time: exactly these five methods must satisfy the provider. Adding a
// sixth to the interface breaks THIS line first.
var _ cliUserspaceControlProvider = fakeUserspaceControl5275{}

// TestUserspaceDataplaneControlResolvesFromTheConstructedHandle pins the
// RUNTIME half: a handle carrying the five methods must actually resolve
// through userspaceDataplaneControl(), and one lacking them must fail rather
// than panic.
//
// This is the test that catches "the CLI was handed a wrapper that does not
// forward the control surface" — the exact regression introduced when #5275
// first routed the CLI through the facade without carrying these five methods
// across.
func TestUserspaceDataplaneControlResolvesFromTheConstructedHandle(t *testing.T) {
	// c.dp is typed as the package-private cliRuntime; a control-capable
	// handle must resolve.
	c := &CLI{dp: struct {
		cliRuntime
		fakeUserspaceControl5275
	}{}}
	provider, err := c.userspaceDataplaneControl()
	if err != nil {
		t.Fatalf("a control-capable handle did not resolve: %v — `request chassis cluster "+
			"data-plane userspace ...` would report the control unavailable", err)
	}
	if provider == nil {
		t.Fatal("resolved provider is nil")
	}

	// A handle WITHOUT the control surface must report unavailable, not panic.
	bare := &CLI{dp: struct{ cliRuntime }{}}
	if _, err := bare.userspaceDataplaneControl(); err == nil {
		t.Fatal("a handle lacking the control surface resolved anyway")
	}
}
