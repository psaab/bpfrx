package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

// #2114: the daemon forwarding-status adapter narrowed to the sampler's
// CachedStatusProvider surface (the IsLoaded/GetMapStats/Status methods
// left the daemon adapter — the gRPC/CLI Build paths construct their own
// per-request adapters and are untouched). These tests pin the narrowed
// contract: per-call probing of the CURRENTLY published dataplane.

type forwardingStatusDaemonTestDP struct {
	runtimeOnlyApplyTestDP
	dataplane.DataPlane
}

// Close/Teardown shadow the ambiguous embedded pair
// (runtimeOnlyApplyTestDP vs the nil dataplane.DataPlane interface).
func (f *forwardingStatusDaemonTestDP) Close() error    { return nil }
func (f *forwardingStatusDaemonTestDP) Teardown() error { return nil }

// forwardingStatusDaemonUserspaceTestDP models the userspace adapter's
// CachedStatus probe surface (#3970).
type forwardingStatusDaemonUserspaceTestDP struct {
	*forwardingStatusDaemonTestDP

	status            dpuserspace.ProcessStatus
	cachedStatusOK    bool
	cachedStatusCalls int
}

func (f *forwardingStatusDaemonUserspaceTestDP) CachedStatus() (dpuserspace.ProcessStatus, bool) {
	f.cachedStatusCalls++
	return f.status, f.cachedStatusOK
}

// TestForwardingStatusAdapterProjectsCachedStatus is the narrowed-adapter
// successor of the pre-#2114 ProjectsMapStats/UsesUserspaceStatusAdapter
// pair: the adapter forwards CachedStatus to the currently published
// userspace dataplane on every call.
func TestForwardingStatusAdapterProjectsCachedStatus(t *testing.T) {
	dp := &forwardingStatusDaemonUserspaceTestDP{
		forwardingStatusDaemonTestDP: &forwardingStatusDaemonTestDP{},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 987,
				WallNS:      654,
			}},
		},
		cachedStatusOK: true,
	}
	d := &Daemon{}
	d.setDataplane(dp)

	provider := d.forwardingStatusDataplane()
	if provider == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	got, ok := provider.CachedStatus()
	if !ok {
		t.Fatal("CachedStatus() ok = false, want true")
	}
	if dp.cachedStatusCalls != 1 {
		t.Fatalf("CachedStatus() calls = %d, want 1", dp.cachedStatusCalls)
	}
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 987 {
		t.Fatalf("CachedStatus() = %#v, want injected userspace status", got)
	}
}

// TestForwardingStatusAdapterNonUserspaceUnavailable pins the
// non-userspace leg: a published dataplane without the CachedStatus probe
// reports ok=false (the sampler holds its last counters), not an error.
func TestForwardingStatusAdapterNonUserspaceUnavailable(t *testing.T) {
	d := &Daemon{}
	d.setDataplane(&forwardingStatusDaemonTestDP{})

	provider := d.forwardingStatusDataplane()
	if provider == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if _, ok := provider.CachedStatus(); ok {
		t.Fatal("CachedStatus() ok = true for a non-userspace dataplane, want false")
	}
}

// TestForwardingStatusAdapterUsesCurrentDataplaneAfterSwap maps the
// pre-#2114 UsesCurrentDataplaneAfterSwap test onto the narrowed shape:
// the single-method adapter probes the CURRENT cell contents per call, so
// a backend swap (or teardown to nil) is picked up on the very next call.
func TestForwardingStatusAdapterUsesCurrentDataplaneAfterSwap(t *testing.T) {
	first := &forwardingStatusDaemonUserspaceTestDP{
		forwardingStatusDaemonTestDP: &forwardingStatusDaemonTestDP{},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 111,
				WallNS:      222,
			}},
		},
		cachedStatusOK: true,
	}
	second := &forwardingStatusDaemonUserspaceTestDP{
		forwardingStatusDaemonTestDP: &forwardingStatusDaemonTestDP{},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 333,
				WallNS:      444,
			}},
		},
		cachedStatusOK: true,
	}
	d := &Daemon{}
	d.setDataplane(first)

	provider := d.forwardingStatusDataplane()
	if provider == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}

	d.setDataplane(second)

	got, ok := provider.CachedStatus()
	if !ok {
		t.Fatal("CachedStatus() after dp swap ok = false, want true")
	}
	if first.cachedStatusCalls != 0 {
		t.Fatalf("first CachedStatus() calls = %d, want 0", first.cachedStatusCalls)
	}
	if second.cachedStatusCalls != 1 {
		t.Fatalf("second CachedStatus() calls = %d, want 1", second.cachedStatusCalls)
	}
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 333 {
		t.Fatalf("CachedStatus() after dp swap = %#v, want second dataplane status", got)
	}

	// Teardown to nil: the next call reports unavailable.
	d.setDataplane(nil)
	if _, ok := provider.CachedStatus(); ok {
		t.Fatal("CachedStatus() after teardown ok = true, want false")
	}
}

// TestForwardingStatusAdapterIsNotDataPlaneAccessor pins the structural
// exclusion (#2114): the collapsed sampler-only adapter must NOT satisfy
// fwdstatus.DataPlaneAccessor, because Build keys backend identity on
// Status() presence and this type can never be routed there. The `var _`
// idiom cannot express the negative, so this is a plain type assertion.
//
// Codex PR #6743 r4-F3: BOTH method sets are checked. Testing only the
// value left an escape — a pointer-receiver Status()/IsLoaded() pair puts
// DataPlaneAccessor on *forwardingStatusDaemonDataPlane and NOT on the
// value, so the value-only assertion stayed green while the pointer form
// became routable the moment the constructor returned an address.
func TestForwardingStatusAdapterIsNotDataPlaneAccessor(t *testing.T) {
	var _ fwdstatus.CachedStatusProvider = forwardingStatusDaemonDataPlane{}

	if _, ok := any(forwardingStatusDaemonDataPlane{}).(fwdstatus.DataPlaneAccessor); ok {
		t.Fatal("forwardingStatusDaemonDataPlane must not satisfy fwdstatus.DataPlaneAccessor")
	}
	if _, ok := any(&forwardingStatusDaemonDataPlane{}).(fwdstatus.DataPlaneAccessor); ok {
		t.Fatal("*forwardingStatusDaemonDataPlane must not satisfy fwdstatus.DataPlaneAccessor " +
			"(a pointer-receiver Status/IsLoaded pair evades the value-only assertion)")
	}
}

// TestForwardingStatusDataplaneConstructionContract pins the narrowed
// constructor contract: nil receiver and NoDataplane mode return nil, but
// an initially-empty cell (bootstrap mode, dataplane constructed but not
// yet armed/published) returns a NON-nil provider whose per-call probe
// reports ok=false until a backend publishes — the pre-#2114 constructor
// returned nil whenever the dataplane field was nil at construction time, permanently
// hiding a later-published backend from the sampler.
func TestForwardingStatusDataplaneConstructionContract(t *testing.T) {
	var nilDaemon *Daemon
	if got := nilDaemon.forwardingStatusDataplane(); got != nil {
		t.Fatalf("nil receiver: forwardingStatusDataplane() = %v, want nil", got)
	}

	noDP := &Daemon{opts: Options{NoDataplane: true}}
	if got := noDP.forwardingStatusDataplane(); got != nil {
		t.Fatalf("NoDataplane: forwardingStatusDataplane() = %v, want nil", got)
	}

	d := &Daemon{}
	provider := d.forwardingStatusDataplane()
	if provider == nil {
		t.Fatal("empty cell: forwardingStatusDataplane() returned nil, want non-nil probing provider")
	}
	if _, ok := provider.CachedStatus(); ok {
		t.Fatal("empty cell: CachedStatus() ok = true, want false")
	}

	// A later publication is picked up by the SAME provider.
	dp := &forwardingStatusDaemonUserspaceTestDP{
		forwardingStatusDaemonTestDP: &forwardingStatusDaemonTestDP{},
		cachedStatusOK:               true,
	}
	d.setDataplane(dp)
	if _, ok := provider.CachedStatus(); !ok {
		t.Fatal("CachedStatus() after publication ok = false, want true")
	}
}
