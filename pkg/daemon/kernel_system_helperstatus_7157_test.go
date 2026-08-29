package daemon

import (
	"os"
	"reflect"
	"strings"
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

// TestDaemonKernelCallSitesUseTheWiredConstructor_7157 binds the CALL SITES, not
// the constructor.
//
// The sibling above calls daemonKernelSystem() directly, so it passes even if
// every production site still uses the bare upgrade.NewKernelSystem() — which is
// exactly what the mutation matrix showed: reverting all three sites left it
// green. A constructor nothing calls is not a fix.
//
// Source-scanned because the choice of constructor is not observable at runtime:
// both return an upgrade.KernelSystem, and the difference (HelperStatus nil or
// not) is precisely what the bare one erases. Comments are stripped first — a
// scan that reads its own prose is satisfied by the sentence describing what it
// should find.
func TestDaemonKernelCallSitesUseTheWiredConstructor_7157(t *testing.T) {
	src, err := os.ReadFile("kernel_selfrecover.go")
	if err != nil {
		t.Fatalf("read kernel_selfrecover.go: %v", err)
	}
	code := stripGoComments7157(string(src))

	if n := strings.Count(code, "upgrade.NewKernelSystem()"); n != 0 {
		t.Errorf("%d call site(s) still use the BARE upgrade.NewKernelSystem(), which leaves "+
			"HelperStatus nil and skips ForwardBeacon's Precondition B — the promotion gate "+
			"then collapses to unit-liveness + a host ping on the self-recover path (#7157)", n)
	}
	// Non-vacuity: the scan must actually be looking at the call sites. If the
	// file stops constructing a kernel system at all, the assertion above is
	// trivially satisfied and this test has quietly stopped guarding anything.
	if n := strings.Count(code, "daemonKernelSystem()"); n == 0 {
		t.Error("kernel_selfrecover.go constructs no kernel system at all, so the check above " +
			"passes vacuously — if the construction moved, move this guard with it")
	}
}

// stripGoComments7157 removes // and /* */ comments so a source scan cannot be
// satisfied by the comment describing what it looks for.
func stripGoComments7157(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "//")
		j := strings.Index(s, "/*")
		switch {
		case i < 0 && j < 0:
			b.WriteString(s)
			return b.String()
		case j < 0 || (i >= 0 && i < j):
			b.WriteString(s[:i])
			nl := strings.IndexByte(s[i:], '\n')
			if nl < 0 {
				return b.String()
			}
			s = s[i+nl:]
		default:
			b.WriteString(s[:j])
			end := strings.Index(s[j:], "*/")
			if end < 0 {
				return b.String()
			}
			s = s[j+end+2:]
		}
	}
}
