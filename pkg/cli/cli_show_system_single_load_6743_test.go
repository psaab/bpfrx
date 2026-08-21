package cli

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Codex PR #6743 r4-F1: the CLI buffer renders must take exactly ONE load
// of the #2114 cell — the same contract showSystemBuffers and
// showSystemBuffersDetail already ASSERTED in their headers.
//
// This file exists because that contract had NO CLI-side test of any kind.
// The gRPC peer had one (server_show_system_single_resolve_6743_test.go),
// and even that one counted Unwrap CALLS rather than cell LOADS, so it
// could not see the residual either. On this side there was nothing at
// all: measured at 6163445e9, reverting the userspace-arm conversion left
// ./pkg/cli/... at rc=0, and the map-stats arm still ended in
// `c.dp.SessionCount()` — a second load — with the header comment as the
// only guard. A comment cannot fail.
//
// The fixture models pkg/daemon's liveDataPlane, where EVERY forwarder
// performs its own cell load (Unwrap reads d.dataplane(); resolve() reads
// it again). A render that loads twice therefore both bumps the counter
// and observably tears, because the cell is empty from load 2 onward.
// That is deterministic, not a race: it is a concurrent setDataplane(nil)
// with the timing removed.

const (
	cliSingleLoadV4 = 7
	cliSingleLoadV6 = 3
)

// cliSingleLoadActiveSessions is the operator-visible consequence of taking
// exactly one load. Under two loads the second resolves the emptied cell,
// SessionCount yields (0,0), and the render's `if v4 > 0 || v6 > 0` gate
// silently drops this line — the firewall reads as having no sessions.
const cliSingleLoadActiveSessions = "Active sessions: 7 IPv4, 3 IPv6, 10 total"

// cliCountingIndirection is a live indirection whose every backend-reaching
// method is a counted cell load. The embedded *dataplane.Manager supplies
// the mandatory cliRuntime surface; the methods below shadow it
// deliberately, because an embedded method is a load the counter cannot
// see — which is exactly how the gRPC peer's guard went blind.
type cliCountingIndirection struct {
	*dataplane.Manager
	backend any
	loads   atomic.Int32
}

func (a *cliCountingIndirection) load() any {
	if a.loads.Add(1) == 1 {
		return a.backend
	}
	return nil
}

func (a *cliCountingIndirection) Unwrap() any { return a.load() }

// SessionCount mirrors liveDataPlane.SessionCount, which resolves the cell
// itself. This is the method the render's tail must NOT call.
func (a *cliCountingIndirection) SessionCount() (int, int) {
	c, ok := a.load().(interface{ SessionCount() (int, int) })
	if !ok {
		return 0, 0
	}
	return c.SessionCount()
}

// GetMapStats mirrors liveDataPlane.GetMapStats for the same reason.
func (a *cliCountingIndirection) GetMapStats() []dataplane.MapStats {
	m, ok := a.load().(interface{ GetMapStats() []dataplane.MapStats })
	if !ok {
		return nil
	}
	return m.GetMapStats()
}

var _ dataplane.LiveUnwrapper = (*cliCountingIndirection)(nil)

// cliMapStatsBackend drives the MAP-STATS arm: no Status(), plus a
// non-empty map list so "No BPF maps available" can only mean the render
// lost the backend.
type cliMapStatsBackend struct {
	*dataplane.Manager
}

func (*cliMapStatsBackend) IsLoaded() bool { return true }

func (*cliMapStatsBackend) SessionCount() (int, int) {
	return cliSingleLoadV4, cliSingleLoadV6
}

func (*cliMapStatsBackend) GetMapStats() []dataplane.MapStats {
	return []dataplane.MapStats{{
		Name:       "sessions_v4",
		Type:       "Hash",
		MaxEntries: 1024,
		UsedCount:  4,
	}}
}

// cliUserspaceArmBackend drives the USERSPACE arm — the arm this PR's diff
// converted here. Without this row the conversion is unbound.
type cliUserspaceArmBackend struct {
	*dataplane.Manager
}

func (*cliUserspaceArmBackend) IsLoaded() bool { return true }

func (*cliUserspaceArmBackend) SessionCount() (int, int) {
	return cliSingleLoadV4, cliSingleLoadV6
}

func (*cliUserspaceArmBackend) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{
		SessionTableEntries: 9,
		MaxSessions:         10,
		NeighborEntries:     6,
		PerBinding: []dpuserspace.BindingCountersSnapshot{{
			UmemTotalFrames:    1000,
			UmemInflightFrames: 800,
			TxRingCapacity:     100,
			OutstandingTX:      90,
			ActiveFlowCount:    4,
			FlowCacheCapacity:  10,
		}},
	}, nil
}

// TestCLIShowSystemBuffersTakesOneCellLoad is the fail-on-revert guard over
// the full render x arm grid.
//
// FAIL-ON-REVERT, per arm:
//
//   - map-stats arm: restore `v4, v6 := c.dp.SessionCount()` in place of
//     backendSessionCount(backend) at the tail of each render. Load 2 hits
//     the emptied cell, SessionCount returns (0,0), and the "Active
//     sessions" line disappears — the loads assertion and the line
//     assertion both go RED.
//   - userspace arm: the same substitution inside the
//     `if provider, ok := backend.(cliUserspaceStatusProvider)` branch.
//     Same two REDs.
func TestCLIShowSystemBuffersTakesOneCellLoad(t *testing.T) {
	renders := []struct {
		name   string
		render func(*CLI) error
	}{
		{"showSystemBuffers", (*CLI).showSystemBuffers},
		{"showSystemBuffersDetail", (*CLI).showSystemBuffersDetail},
	}
	arms := []struct {
		name       string
		backend    func() any
		wantMarker string
	}{
		{
			name:       "mapStatsArm",
			backend:    func() any { return &cliMapStatsBackend{Manager: dataplane.New()} },
			wantMarker: "sessions_v4",
		},
		{
			name:       "userspaceArm",
			backend:    func() any { return &cliUserspaceArmBackend{Manager: dataplane.New()} },
			wantMarker: "Userspace Buffer Utilization:",
		},
	}

	for _, render := range renders {
		for _, arm := range arms {
			t.Run(render.name+"/"+arm.name, func(t *testing.T) {
				dp := &cliCountingIndirection{
					Manager: dataplane.New(),
					backend: arm.backend(),
				}
				c := &CLI{dp: dp}

				var renderErr error
				out := captureStdout(t, func() {
					renderErr = render.render(c)
				})
				if renderErr != nil {
					t.Fatalf("%s/%s: %v", render.name, arm.name, renderErr)
				}

				if strings.Contains(out, "No BPF maps available") {
					t.Fatalf("%s/%s reported \"No BPF maps available\" after taking more "+
						"than one cell load (loads=%d): the render must take ONE load and "+
						"describe that instant.\n%s",
						render.name, arm.name, dp.loads.Load(), out)
				}
				if !strings.Contains(out, arm.wantMarker) {
					t.Fatalf("%s/%s did not render the published backend's %s body "+
						"(loads=%d); missing %q\n%s",
						render.name, arm.name, arm.name, dp.loads.Load(), arm.wantMarker, out)
				}
				if !strings.Contains(out, cliSingleLoadActiveSessions) {
					t.Fatalf("%s/%s dropped the session-count line (loads=%d): want %q. "+
						"The tail must read backendSessionCount(backend), not "+
						"c.dp.SessionCount() — the latter loads the cell a second time "+
						"and reports (0,0) against the emptied cell.\n%s",
						render.name, arm.name, dp.loads.Load(), cliSingleLoadActiveSessions, out)
				}
				if got := dp.loads.Load(); got != 1 {
					t.Fatalf("%s/%s loaded the cell %d times, want exactly 1",
						render.name, arm.name, got)
				}
			})
		}
	}
}

// TestCLICountingIndirectionErasesStatus is fixture fidelity: the
// indirection must NOT itself satisfy cliUserspaceStatusProvider, or the
// userspace-arm rows would pass with no unwrap at all and the grid would be
// vacuous in the arm this PR changed.
func TestCLICountingIndirectionErasesStatus(t *testing.T) {
	dp := &cliCountingIndirection{
		Manager: dataplane.New(),
		backend: &cliUserspaceArmBackend{Manager: dataplane.New()},
	}
	if _, ok := any(dp).(cliUserspaceStatusProvider); ok {
		t.Fatal("fixture drift: cliCountingIndirection implements " +
			"cliUserspaceStatusProvider directly, so the userspace-arm rows no " +
			"longer exercise a resolution")
	}
	if got := dp.loads.Load(); got != 0 {
		t.Fatalf("fixture drift: constructing cliCountingIndirection loaded the cell %d times, want 0", got)
	}
}

// TestCLIShowSystemBuffersEmptyCellSaysNotLoaded is the negative control:
// with NO backend the renders must say "Dataplane not loaded", so the grid
// above cannot pass merely because a string was deleted.
func TestCLIShowSystemBuffersEmptyCellSaysNotLoaded(t *testing.T) {
	for _, render := range []struct {
		name   string
		render func(*CLI) error
	}{
		{"showSystemBuffers", (*CLI).showSystemBuffers},
		{"showSystemBuffersDetail", (*CLI).showSystemBuffersDetail},
	} {
		t.Run(render.name, func(t *testing.T) {
			c := &CLI{dp: &cliCountingIndirection{Manager: dataplane.New(), backend: nil}}
			var renderErr error
			out := captureStdout(t, func() {
				renderErr = render.render(c)
			})
			if renderErr != nil {
				t.Fatalf("%s: %v", render.name, renderErr)
			}
			if !strings.Contains(out, "Dataplane not loaded") {
				t.Fatalf("%s: empty cell must render \"Dataplane not loaded\", got:\n%s",
					render.name, out)
			}
		})
	}
}
