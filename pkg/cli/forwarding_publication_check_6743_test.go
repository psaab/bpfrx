package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

// #6743 r2 B7 (pkg/cli half): `show chassis forwarding` must not publish a
// TRUSTED zero for a daemon that has no backend.
//
// forwardingStatusDataplane() gated on `c.dp == nil`, which is permanently
// false under the daemon's live indirection, so an emptied cell returned
// the non-userspace `base` wrapper; fwdstatus.Build then took its BPF-map
// arm and set BufferKnown=true with BufferPercent=0. See the gRPC peer,
// pkg/grpcapi/forwarding_publication_check_6743_test.go, for the full
// argument and the measured before/after; this is the same accessor behind
// the local console.

// fwdLiveIndirectionCLI6743 is the daemon's live adapter shape for this
// render: it satisfies the MANDATORY cliRuntime surface itself and
// resolves the published backend through Unwrap. Its own GetMapStats
// returns nil, which is what liveDataPlane's forwarder returns on an
// unresolved cell.
type fwdLiveIndirectionCLI6743 struct {
	*forwardingStatusCLITestDP
	backend any
}

func (f *fwdLiveIndirectionCLI6743) Unwrap() any { return f.backend }

// errProcReaderCLI6743 makes fwdstatus.Build take its documented "bypass
// /proc" path so Buffer% is the only thing under test.
type errProcReaderCLI6743 struct{}

func (errProcReaderCLI6743) ReadSelfStat() (fwdstatus.ProcSelfStat, error) {
	return fwdstatus.ProcSelfStat{}, errNoProcCLI6743{}
}

func (errProcReaderCLI6743) ReadSelfStatm() (fwdstatus.ProcSelfStatm, error) {
	return fwdstatus.ProcSelfStatm{}, errNoProcCLI6743{}
}

func (errProcReaderCLI6743) ReadStat() (fwdstatus.ProcStat, error) {
	return fwdstatus.ProcStat{}, errNoProcCLI6743{}
}

func (errProcReaderCLI6743) ReadMemInfo() (fwdstatus.ProcMemInfo, error) {
	return fwdstatus.ProcMemInfo{}, errNoProcCLI6743{}
}

func (errProcReaderCLI6743) ReadCgroupMemoryMax() (uint64, error) {
	return 0, errNoProcCLI6743{}
}

type errNoProcCLI6743 struct{}

func (errNoProcCLI6743) Error() string { return "proc unavailable (test stub)" }

func buildForwardingCLI6743(t *testing.T, c *CLI) (*fwdstatus.ForwardingStatus, string) {
	t.Helper()
	fs, err := fwdstatus.Build(
		c.forwardingStatusDataplane(),
		errProcReaderCLI6743{},
		time.Now(),
		fwdstatus.SamplerSnapshot{},
	)
	if err != nil {
		t.Fatalf("fwdstatus.Build: %v", err)
	}
	return fs, fwdstatus.Format(fs)
}

// TestCLIForwardingStatusReportsUnknownBufferOnAnEmptyCell_6743 is the
// fail-on-revert guard.
//
// RED-on-revert: restore `if c == nil || c.dp == nil` in front of the probe
// in forwardingStatusDataplane (pkg/cli/cli_show_chassis.go).
func TestCLIForwardingStatusReportsUnknownBufferOnAnEmptyCell_6743(t *testing.T) {
	live := &fwdLiveIndirectionCLI6743{
		forwardingStatusCLITestDP: &forwardingStatusCLITestDP{loaded: true},
		backend:                   nil, // published NOTHING
	}
	c := &CLI{dp: live}

	if c.dp == nil {
		t.Fatal("fixture broken: c.dp is nil, so the old `dp == nil` check would already " +
			"answer correctly and this test proves nothing")
	}

	if got := c.forwardingStatusDataplane(); got != nil {
		t.Errorf("forwardingStatusDataplane() on an EMPTY cell = %T, want nil", got)
	}

	fs, out := buildForwardingCLI6743(t, c)

	if fs.BufferKnown {
		t.Fatalf("BufferKnown = true (BufferPercent = %.0f) on an EMPTY cell: the render "+
			"certifies a zero it invented for a daemon with no backend (#6743 r2-B7)",
			fs.BufferPercent)
	}
	if strings.Contains(out, "Buffer utilization   0 percent") {
		t.Fatalf("render says %q on an EMPTY cell; want the unknown form",
			"Buffer utilization   0 percent")
	}
	if !strings.Contains(out, "unknown") {
		t.Fatalf("render = %q; want a Buffer utilization row reading unknown", out)
	}
}

// TestCLIForwardingStatusNilDataplaneControl_6743 is the control the
// finding was measured against, in a SEPARATE body.
func TestCLIForwardingStatusNilDataplaneControl_6743(t *testing.T) {
	c := &CLI{dp: nil}

	if got := c.forwardingStatusDataplane(); got != nil {
		t.Fatalf("forwardingStatusDataplane() with a nil dp = %T, want nil", got)
	}
	fs, out := buildForwardingCLI6743(t, c)
	if fs.BufferKnown {
		t.Fatal("control broken: BufferKnown = true with a NIL dp, so the empty-cell " +
			"assertion is not measuring a divergence")
	}
	if !strings.Contains(out, "unknown") {
		t.Fatalf("control render = %q; want the unknown form", out)
	}
}

// TestCLIForwardingStatusStillBuildsForAPublishedBackend_6743 is the
// over-reach control, in a SEPARATE body: the fix must not collapse into
// "always return nil".
func TestCLIForwardingStatusStillBuildsForAPublishedBackend_6743(t *testing.T) {
	published := &forwardingStatusCLITestDP{loaded: true} // no Status(): non-userspace
	if _, ok := any(published).(cliUserspaceStatusProvider); ok {
		t.Fatal("fixture broken: the published backend carries Status(), so this is the " +
			"userspace arm, not the map arm")
	}
	if _, ok := any(published).(dataplane.LiveUnwrapper); ok {
		t.Fatal("fixture broken: the published backend is itself an unwrapper, so " +
			"dataplane.Unwrap resolves PAST it and this is the empty-cell arm")
	}

	live := &fwdLiveIndirectionCLI6743{
		// The map stats come off the INDIRECTION because that is what the
		// `base` wrapper delegates GetMapStats() to (cli_show_chassis.go).
		forwardingStatusCLITestDP: &forwardingStatusCLITestDP{
			loaded: true,
			mapStats: []dataplane.MapStats{
				{Name: "sessions", Type: "Hash", MaxEntries: 200, UsedCount: 50},
			},
		},
		backend: published,
	}
	c := &CLI{dp: live}

	if c.forwardingStatusDataplane() == nil {
		t.Fatal("forwardingStatusDataplane() = nil for a PUBLISHED backend: the " +
			"publication check has collapsed into an unconditional nil, so the console " +
			"reports unknown for a healthy firewall")
	}

	fs, out := buildForwardingCLI6743(t, c)
	if !fs.BufferKnown {
		t.Fatal("BufferKnown = false for a PUBLISHED backend with map stats: the fix " +
			"traded a false-trusted zero for a permanent unknown")
	}
	if fs.BufferPercent != 25 {
		t.Fatalf("BufferPercent = %.2f, want 25 (50/200)", fs.BufferPercent)
	}
	if !strings.Contains(out, "25 percent") {
		t.Fatalf("render = %q; want a Buffer utilization row of 25 percent", out)
	}
}

// TestCLIForwardingStatusStillSelectsTheUserspaceAdapter_6743 is the second
// over-reach control: a PUBLISHED userspace backend must still route to the
// Status()-carrying adapter rather than the BPF-map arm.
func TestCLIForwardingStatusStillSelectsTheUserspaceAdapter_6743(t *testing.T) {
	published := &forwardingStatusCLIUserspaceTestDP{
		forwardingStatusCLITestDP: &forwardingStatusCLITestDP{loaded: true},
	}
	live := &fwdLiveIndirectionCLI6743{
		forwardingStatusCLITestDP: &forwardingStatusCLITestDP{loaded: true},
		backend:                   published,
	}
	c := &CLI{dp: live}

	accessor := c.forwardingStatusDataplane()
	if _, ok := accessor.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); !ok {
		t.Fatalf("forwardingStatusDataplane() = %T for a PUBLISHED USERSPACE backend, "+
			"want the Status()-carrying adapter", accessor)
	}
}
