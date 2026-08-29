package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade"
)

// #7157: the daemon's kernel-channel construction sites must wire Gate 4's
// #6607 dataplane-liveness probe. With HelperStatus nil, ForwardBeacon's
// Precondition B (`if s.HelperStatus != nil`) is skipped entirely and the
// promotion gate collapses to unit-liveness plus a host ping — which passes on a
// box whose helper is down, stale or crash-looping.
//
// This asserts the WIRING, not the probe: the probe is pkg/upgrade's and is
// tested there. What was missing was a caller.
func TestDaemonKernelSystemWiresHelperStatus_7157(t *testing.T) {
	sys := daemonKernelSystem()

	// Read through reflection, NOT a type assertion. realKernelSystem's FIELDS
	// are exported but its TYPE is not, so no assertion outside pkg/upgrade can
	// name it — and an interface assertion for accessors that do not exist
	// SKIPS, which binds nothing. A skipped cell here would have looked like
	// coverage for the exact wiring this issue is about.
	v := reflect.Indirect(reflect.ValueOf(sys))
	if v.Kind() != reflect.Struct {
		t.Fatalf("kernel system is %s, not a struct — if the constructor changed shape, "+
			"update this guard rather than deleting it; the wiring it binds is still the "+
			"difference between Gate 4 and a host ping", v.Kind())
	}
	hs := v.FieldByName("HelperStatus")
	if !hs.IsValid() {
		t.Fatal("no HelperStatus field: the wiring this test exists for cannot be observed")
	}
	if hs.IsNil() {
		t.Error("HelperStatus is nil, so ForwardBeacon's Precondition B (`if s.HelperStatus " +
			"!= nil`) is skipped and the promotion gate collapses to unit-liveness + a host " +
			"ping. cmd/xpfd wires it via NewKernelSystemWithHelperStatus; the daemon " +
			"self-recover path must not be the weaker of two callers of one gate (#7157)")
	}
	sock := v.FieldByName("ControlSocket")
	if !sock.IsValid() || sock.String() == "" {
		t.Error("no control socket, so HelperStatus cannot reach the helper even though it " +
			"is wired")
	}
}

// The adapter must treat "no live status" as NOT ready. A helper that answers
// !ok has not proved it is forwarding, and reading that as ready is exactly the
// false-PASS Gate 4 exists to prevent.
func TestDaemonHelperStatusNilIsNotReady_7157(t *testing.T) {
	// An unreachable socket: ProbeStatus errors or yields no status; either way
	// the adapter must report not-enabled, not-armed.
	enabled, armed, _, err := daemonUpgradeHelperStatus("/nonexistent/xpf-7157.sock", 0)
	if enabled || armed {
		t.Errorf("an unreachable helper reported enabled=%v armed=%v; a probe that could not "+
			"reach the helper has not proved forwarding and must not satisfy Gate 4 "+
			"(err=%v)", enabled, armed, err)
	}
}

// Compile-time: the constructor must satisfy the interface the runner takes, so
// a signature drift in pkg/upgrade breaks the build here rather than silently
// leaving the daemon on the bare constructor again.
var _ upgrade.KernelSystem = daemonKernelSystem()
