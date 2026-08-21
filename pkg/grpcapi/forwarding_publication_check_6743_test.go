package grpcapi

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

// #6743 r2 B7: `show chassis forwarding` must not publish a TRUSTED zero
// for a daemon that has no backend.
//
// This is the same r6-F3 class as the WireGuard renders
// (wireguard_publication_check_6743_test.go), one step worse. Those answer
// with a misleading STRING, which a human reads and can question.
// forwardingStatusDataplane() gated on `s.dp == nil` — permanently false
// under the daemon's live indirection — so an emptied cell fell PAST the
// guard and returned the non-userspace `base` wrapper. fwdstatus.Build
// then takes its `dp != nil && !isUserspace` arm, iterates the (empty)
// GetMapStats(), leaves maxPct at 0, and sets:
//
//	fs.BufferPercent = 0
//	fs.BufferKnown   = true      <- builder.go:145
//
// MEASURED at 710a87569, before the fix:
//
//	EMPTY-CELL  "Buffer utilization   0 percent"
//	NIL-DP      "Buffer utilization   unknown (see #878)"   <- the control
//
// BufferKnown is not cosmetic. It is the field every downstream consumer
// reads to decide whether the number means anything (fwdstatus.go:100
// picks the "unknown" rendering off it), so the defect does not merely
// print a wrong string — it tells consumers the wrong string is
// trustworthy. The assertions below are therefore on BufferKnown FIRST and
// on the rendered text second; a fix that only changed the string would
// pass a text-only guard and leave the trust bit inverted.
//
// The peer guard for pkg/cli's identical accessor is
// pkg/cli/forwarding_publication_check_6743_test.go.

// fwdLiveIndirection6743 is the daemon's live adapter shape for this
// render: it satisfies the MANDATORY grpcRuntime surface itself (via the
// embedded test DP, exactly as liveDataPlane satisfies it via its
// forwarders) and resolves the published backend through Unwrap.
//
// Its own GetMapStats returns nil, which is what liveDataPlane's forwarder
// returns on an unresolved cell — so the "0 percent" reproduction is the
// production shape, not a contrived one.
type fwdLiveIndirection6743 struct {
	*forwardingStatusServerTestDP
	backend any
}

func (f *fwdLiveIndirection6743) Unwrap() any { return f.backend }

// errProcReader6743 makes fwdstatus.Build take its documented "bypass
// /proc" path, so Buffer% is the only thing under test here. Build
// tolerates every one of these errors.
type errProcReader6743 struct{}

func (errProcReader6743) ReadSelfStat() (fwdstatus.ProcSelfStat, error) {
	return fwdstatus.ProcSelfStat{}, errNoProc6743
}

func (errProcReader6743) ReadSelfStatm() (fwdstatus.ProcSelfStatm, error) {
	return fwdstatus.ProcSelfStatm{}, errNoProc6743
}

func (errProcReader6743) ReadStat() (fwdstatus.ProcStat, error) {
	return fwdstatus.ProcStat{}, errNoProc6743
}

func (errProcReader6743) ReadMemInfo() (fwdstatus.ProcMemInfo, error) {
	return fwdstatus.ProcMemInfo{}, errNoProc6743
}

func (errProcReader6743) ReadCgroupMemoryMax() (uint64, error) { return 0, errNoProc6743 }

var errNoProc6743 = errProcUnavailable6743{}

type errProcUnavailable6743 struct{}

func (errProcUnavailable6743) Error() string { return "proc unavailable (test stub)" }

// buildForwarding6743 runs the production render path end to end for s.
func buildForwarding6743(t *testing.T, s *Server) (*fwdstatus.ForwardingStatus, string) {
	t.Helper()
	fs, err := fwdstatus.Build(
		s.forwardingStatusDataplane(),
		errProcReader6743{},
		time.Now(),
		fwdstatus.SamplerSnapshot{},
	)
	if err != nil {
		t.Fatalf("fwdstatus.Build: %v", err)
	}
	return fs, fwdstatus.Format(fs)
}

// TestForwardingStatusReportsUnknownBufferOnAnEmptyCell_6743 is the
// fail-on-revert guard.
//
// RED-on-revert: restore `if s == nil || s.dp == nil` in front of the
// probe in forwardingStatusDataplane (pkg/grpcapi/server_show_forwarding.go).
func TestForwardingStatusReportsUnknownBufferOnAnEmptyCell_6743(t *testing.T) {
	live := &fwdLiveIndirection6743{
		forwardingStatusServerTestDP: &forwardingStatusServerTestDP{loaded: true},
		backend:                      nil, // published NOTHING
	}
	s := &Server{dp: live}

	// PRECONDITION: the shape under test is "the field is non-nil but
	// nothing is published". Without this a nil-dp fixture would pass for
	// the wrong reason.
	if s.dp == nil {
		t.Fatal("fixture broken: s.dp is nil, so the old `dp == nil` check would already " +
			"answer correctly and this test proves nothing")
	}

	if got := s.forwardingStatusDataplane(); got != nil {
		t.Errorf("forwardingStatusDataplane() on an EMPTY cell = %T, want nil — a non-nil "+
			"accessor sends fwdstatus.Build into an arm that describes a backend the "+
			"daemon does not have", got)
	}

	fs, out := buildForwarding6743(t, s)

	// THE PROPERTY, asserted on the trust bit before the text.
	if fs.BufferKnown {
		t.Fatalf("BufferKnown = true (BufferPercent = %.0f) on an EMPTY cell. Every "+
			"downstream consumer reads BufferKnown to decide whether the number means "+
			"anything, so this does not merely render a wrong string — it certifies it "+
			"(#6743 r2-B7)", fs.BufferPercent)
	}
	if strings.Contains(out, "Buffer utilization   0 percent") {
		t.Fatalf("render says %q on an EMPTY cell; want the unknown form",
			"Buffer utilization   0 percent")
	}
	if !strings.Contains(out, "unknown") {
		t.Fatalf("render = %q; want a Buffer utilization row reading unknown", out)
	}
}

// TestForwardingStatusNilDataplaneControl_6743 is the CONTROL the finding
// was measured against: with a genuinely nil dp the render already answered
// correctly, which is why the empty-cell divergence above is a defect and
// not a pre-existing limitation of Build.
//
// It is a separate body so it is observed running under the same mutation
// the guard above exists to bound, rather than sitting behind that body's
// t.Fatalf.
func TestForwardingStatusNilDataplaneControl_6743(t *testing.T) {
	s := &Server{dp: nil}

	if got := s.forwardingStatusDataplane(); got != nil {
		t.Fatalf("forwardingStatusDataplane() with a nil dp = %T, want nil", got)
	}
	fs, out := buildForwarding6743(t, s)
	if fs.BufferKnown {
		t.Fatal("control broken: BufferKnown = true with a NIL dp, so the empty-cell " +
			"assertion is not measuring a divergence")
	}
	if !strings.Contains(out, "unknown") {
		t.Fatalf("control render = %q; want the unknown form", out)
	}
}

// TestForwardingStatusStillBuildsForAPublishedBackend_6743 is the
// over-reach control, in a SEPARATE body: the fix must not collapse into
// "always return nil". A backend that IS published must still get an
// accessor, and its map stats must still produce a KNOWN buffer number —
// otherwise the fix would trade a false-trusted zero for a permanent
// "unknown" and no test would notice.
func TestForwardingStatusStillBuildsForAPublishedBackend_6743(t *testing.T) {
	published := &forwardingStatusServerTestDP{loaded: true} // no Status(): non-userspace
	if _, ok := any(published).(userspaceStatusProvider); ok {
		t.Fatal("fixture broken: the published backend carries Status(), so this is the " +
			"userspace arm, not the map arm")
	}
	if _, ok := any(published).(dataplane.LiveUnwrapper); ok {
		t.Fatal("fixture broken: the published backend is itself an unwrapper, so " +
			"dataplane.Unwrap resolves PAST it and this is the empty-cell arm")
	}

	live := &fwdLiveIndirection6743{
		// The map stats come off the INDIRECTION because that is what the
		// `base` wrapper delegates GetMapStats() to (server_show_forwarding.go).
		forwardingStatusServerTestDP: &forwardingStatusServerTestDP{
			loaded: true,
			mapStats: []dataplane.MapStats{
				{Name: "sessions", Type: "Hash", MaxEntries: 200, UsedCount: 50},
			},
		},
		backend: published,
	}
	s := &Server{dp: live}

	accessor := s.forwardingStatusDataplane()
	if accessor == nil {
		t.Fatal("forwardingStatusDataplane() = nil for a PUBLISHED backend: the " +
			"publication check has collapsed into an unconditional nil, so `show chassis " +
			"forwarding` reports unknown for a healthy firewall")
	}

	fs, out := buildForwarding6743(t, s)
	if !fs.BufferKnown {
		t.Fatal("BufferKnown = false for a PUBLISHED backend with map stats: the fix " +
			"traded a false-trusted zero for a permanent unknown")
	}
	if fs.BufferPercent != 25 {
		t.Fatalf("BufferPercent = %.2f, want 25 (50/200) — the map arm did not read the "+
			"published backend's stats", fs.BufferPercent)
	}
	if !strings.Contains(out, "25 percent") {
		t.Fatalf("render = %q; want a Buffer utilization row of 25 percent", out)
	}
}

// TestForwardingStatusStillSelectsTheUserspaceAdapter_6743 is the second
// over-reach control: the single resolution must still route a PUBLISHED
// userspace backend to the Status()-carrying adapter. Without this, a fix
// that resolved correctly but asserted against the wrong value would
// silently downgrade every userspace deployment to the map arm — the same
// class of erasure B1 covers for dpProbe().
func TestForwardingStatusStillSelectsTheUserspaceAdapter_6743(t *testing.T) {
	published := &forwardingStatusServerUserspaceTestDP{
		forwardingStatusServerTestDP: &forwardingStatusServerTestDP{loaded: true},
	}
	live := &fwdLiveIndirection6743{
		forwardingStatusServerTestDP: &forwardingStatusServerTestDP{loaded: true},
		backend:                      published,
	}
	s := &Server{dp: live}

	accessor := s.forwardingStatusDataplane()
	if _, ok := accessor.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); !ok {
		t.Fatalf("forwardingStatusDataplane() = %T for a PUBLISHED USERSPACE backend, "+
			"want the Status()-carrying adapter. Asserting against the indirection "+
			"instead of the resolved backend erases the capability on a healthy "+
			"deployment and drops the render into the BPF-map arm", accessor)
	}
}
