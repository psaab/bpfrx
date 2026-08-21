package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #2114 (Codex PR #6743 r6-F1): the SECOND optional-capability family.
//
// The erasure has two independent code paths, and a fix that reaches only
// one of them reads green while the other stays broken:
//
//   - Family 1 — the three `...Of(provider any)` helpers in
//     pkg/dataplane/apply.go (LastApplyResultOf / SessionStoreOf /
//     TelemetryOf). Bound in pkg/daemon's
//     daemon_dp_capability_2114_test.go.
//   - Family 2 — NAMED interfaces asserted against the consumer's stored
//     `dp` field. In this package that is cliUserspaceStatusProvider
//     (`Status()`, consumed by cli_show_system.go, cli_show_chassis.go and
//     cli_show_security_wireguard.go) and cliUserspaceControlProvider
//     (Status + the four `request chassis cluster data-plane userspace
//     ...` mutators, consumed by cli_request.go). These live entirely in
//     pkg/cli and never touch apply.go, so the family-1 guards say nothing
//     about them.
//
// pkg/daemon cannot host this test — it is pkg/cli that pkg/daemon
// imports, so the real liveDataPlane is unreachable from here. The fixture
// below reproduces its ESSENTIAL property instead: a value that satisfies
// the mandatory cliRuntime surface, does NOT itself implement the optional
// provider interfaces, and resolves the real backend per call through
// dataplane.LiveUnwrapper. The test asserts that erasure property directly
// (cliLiveIndirectionErasesStatus) so the fixture cannot silently drift
// into carrying Status() and make the guards vacuous.

// cliLiveIndirection aliases pkg/daemon's liveDataPlane: the embedded
// *dataplane.Manager supplies the mandatory cliRuntime surface and nothing
// else — in particular no Status() and none of the four control mutators.
type cliLiveIndirection struct {
	*dataplane.Manager
	backend any
}

func (a cliLiveIndirection) Unwrap() any { return a.backend }

const cliProbeThreadCPUNS = 91733

// cliUserspaceBackend is the PUBLISHED backend. It carries the whole
// cliUserspaceControlProvider set, so one fixture covers both named
// interfaces this package probes for.
type cliUserspaceBackend struct {
	*dataplane.Manager
	armedCalls  int
	armedWanted bool
}

func newCLIUserspaceBackend() *cliUserspaceBackend {
	return &cliUserspaceBackend{Manager: dataplane.New()}
}

func (b *cliUserspaceBackend) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{ThreadCPUNS: cliProbeThreadCPUNS}},
	}, nil
}

func (b *cliUserspaceBackend) SetForwardingArmed(armed bool) (dpuserspace.ProcessStatus, error) {
	b.armedCalls++
	b.armedWanted = armed
	return b.Status()
}

func (b *cliUserspaceBackend) SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	return b.Status()
}

func (b *cliUserspaceBackend) SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	return b.Status()
}

func (b *cliUserspaceBackend) InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error) {
	return b.Status()
}

// newCLIWithLiveIndirection wires a CLI exactly as the daemon does: the dp
// field holds the indirection, not the backend.
func newCLIWithLiveIndirection(t *testing.T, backend any) (*CLI, cliLiveIndirection) {
	t.Helper()
	adapter := cliLiveIndirection{Manager: dataplane.New(), backend: backend}

	// FIXTURE FIDELITY: the adapter must itself FAIL both probes, or these
	// tests would pass with no unwrap at all.
	if _, ok := any(adapter).(cliUserspaceStatusProvider); ok {
		t.Fatal("fixture drift: cliLiveIndirection implements cliUserspaceStatusProvider directly, " +
			"so it no longer reproduces the capability erasure under test")
	}
	if _, ok := any(adapter).(cliUserspaceControlProvider); ok {
		t.Fatal("fixture drift: cliLiveIndirection implements cliUserspaceControlProvider directly")
	}
	return &CLI{dp: adapter}, adapter
}

// TestCLIProbe_StatusSurvivesLiveIndirection is family 2's preservation
// guard for cliUserspaceStatusProvider.
//
// Fail-on-revert: change pkg/cli's dpProbe() back to returning c.dp
// unwrapped and the probe is made against the indirection, whose method
// set has no Status() — `show system buffers` / `show chassis cluster
// data-plane` / `show security wireguard` all silently lose the userspace
// answer for a running helper.
func TestCLIProbe_StatusSurvivesLiveIndirection(t *testing.T) {
	backend := newCLIUserspaceBackend()
	c, _ := newCLIWithLiveIndirection(t, backend)

	// CONTROL: the backend really has the capability, so a RED below is
	// about the probe rather than about a fake that never implemented it.
	if _, ok := any(backend).(cliUserspaceStatusProvider); !ok {
		t.Fatal("control: the published backend does not implement cliUserspaceStatusProvider")
	}

	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		t.Fatalf("userspaceDataplaneStatus() = %v for a HEALTHY published backend that implements "+
			"Status(): the live indirection erased the capability, so every userspace answer in "+
			"pkg/cli degrades to \"unavailable\"", err)
	}
	if len(status.WorkerRuntime) != 1 || status.WorkerRuntime[0].ThreadCPUNS != cliProbeThreadCPUNS {
		t.Fatalf("userspaceDataplaneStatus() = %+v, want the published backend's status "+
			"(ThreadCPUNS %d)", status, cliProbeThreadCPUNS)
	}
}

// TestCLIProbe_ControlProviderSurvivesLiveIndirection is family 2's
// preservation guard for the MUTATING half — the four methods behind
// `request chassis cluster data-plane userspace ...`. Separate body from
// the status guard: sharing one would let a status failure skip this
// entirely.
//
// Fail-on-revert: same dpProbe() revert — `userspaceDataplaneControl()`
// returns "userspace dataplane control unavailable" and the operator's
// arm/disarm, queue, binding and inject commands stop working against a
// perfectly healthy helper.
func TestCLIProbe_ControlProviderSurvivesLiveIndirection(t *testing.T) {
	backend := newCLIUserspaceBackend()
	c, _ := newCLIWithLiveIndirection(t, backend)

	if _, ok := any(backend).(cliUserspaceControlProvider); !ok {
		t.Fatal("control: the published backend does not implement cliUserspaceControlProvider")
	}

	provider, err := c.userspaceDataplaneControl()
	if err != nil {
		t.Fatalf("userspaceDataplaneControl() = %v for a HEALTHY published backend that implements "+
			"the control set: the live indirection erased it, so `request chassis cluster "+
			"data-plane userspace ...` is unavailable", err)
	}
	if _, err := provider.SetForwardingArmed(true); err != nil {
		t.Fatalf("SetForwardingArmed through the probe: %v", err)
	}
	if backend.armedCalls != 1 || !backend.armedWanted {
		t.Fatalf("SetForwardingArmed reached the backend %d times (armed=%v), want 1 (armed=true): "+
			"the probe resolved to something other than the published backend",
			backend.armedCalls, backend.armedWanted)
	}
}

// TestCLIProbe_DisownedBackendIsUnreachable is family 2's mirror of the
// family-1 unreachability guard: Unwrap restoring capabilities must not
// also restore a backend the daemon has disowned. An empty cell surfaces
// here as Unwrap returning nil.
//
// Fail-on-revert: make the unwrap fall back to the raw handle (or cache a
// previously resolved backend) and these calls succeed against a dataplane
// the daemon no longer publishes.
func TestCLIProbe_DisownedBackendIsUnreachable(t *testing.T) {
	c, _ := newCLIWithLiveIndirection(t, nil) // nil backend == emptied cell

	if _, err := c.userspaceDataplaneStatus(); err == nil {
		t.Fatal("userspaceDataplaneStatus() succeeded against a DISOWNED backend: the probe " +
			"resolved something the daemon no longer publishes")
	}
	if _, err := c.userspaceDataplaneControl(); err == nil {
		t.Fatal("userspaceDataplaneControl() succeeded against a DISOWNED backend")
	}
}
