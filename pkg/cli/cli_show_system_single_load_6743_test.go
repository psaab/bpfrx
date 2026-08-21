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
// The fixture models pkg/daemon's liveDataPlane, where a forwarder
// performs its own cell load (Unwrap reads d.dataplane(); resolve() reads
// it again). Its reach is TOTAL over cliRuntime's 25 methods, and by
// construction rather than by count:
//
//   - the three declared below (Unwrap, SessionCount, GetMapStats) each
//     take their own counted load;
//   - EVERY OTHER method PANICS, because the embedded cliRuntime is a nil
//     interface and promotion dispatches all 22 undeclared methods through
//     it. None of them can quietly answer.
//
// That is the r4 correction: r4 embedded a concrete *dataplane.Manager,
// which SERVED those 22 — closing 2 of 25 while the header claimed all of
// them. Bound now by TestCLICountingIndirectionServesNothingSilently.
//
// A render that loads twice through a DECLARED method both bumps the
// counter and observably tears, because the cell is empty from load 2
// onward. That is deterministic, not a race: it is a concurrent
// setDataplane(nil) with the timing removed.

const (
	cliSingleLoadV4 = 7
	cliSingleLoadV6 = 3
)

// cliSingleLoadActiveSessions is the operator-visible consequence of taking
// exactly one load. Under two loads the second resolves the emptied cell,
// SessionCount yields (0,0), and the render's `if v4 > 0 || v6 > 0` gate
// silently drops this line — the firewall reads as having no sessions.
const cliSingleLoadActiveSessions = "Active sessions: 7 IPv4, 3 IPv6, 10 total"

// cliCountingIndirection is a live indirection whose backend-reaching
// methods are counted cell loads.
//
// The embedded cliRuntime is a nil INTERFACE, never a concrete value. It
// is what makes this value assignable to CLI.dp — the promoted method set
// is cliRuntime's — and simultaneously what makes the counter's reach
// total: the three methods below shadow their promoted counterparts, and
// every OTHER promoted method dispatches through a nil interface and
// panics at the production call site that took it.
//
// Do NOT restore the r4 `*dataplane.Manager` embed. A concrete embed
// satisfies the same field while SERVING the 22 undeclared methods, so a
// render reaching the backend through any of them takes a load this
// fixture cannot see — which is exactly how the gRPC peer's guard went
// blind. TestCLICountingIndirectionServesNothingSilently binds it.
type cliCountingIndirection struct {
	cliRuntime
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

var (
	_ dataplane.LiveUnwrapper = (*cliCountingIndirection)(nil)
	// The nil embed is what makes the fixture storable in CLI.dp. If this
	// assertion ever needs a concrete embed to hold, the counter has lost
	// its reach — see the type's doc comment.
	_ cliRuntime = (*cliCountingIndirection)(nil)
)

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
				dp := &cliCountingIndirection{backend: arm.backend()}
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
	dp := &cliCountingIndirection{backend: &cliUserspaceArmBackend{Manager: dataplane.New()}}
	if _, ok := any(dp).(cliUserspaceStatusProvider); ok {
		t.Fatal("fixture drift: cliCountingIndirection implements " +
			"cliUserspaceStatusProvider directly, so the userspace-arm rows no " +
			"longer exercise a resolution")
	}
	if got := dp.loads.Load(); got != 0 {
		t.Fatalf("fixture drift: constructing cliCountingIndirection loaded the cell %d times, want 0", got)
	}
}

// TestCLICountingIndirectionServesNothingSilently is what makes the grid's
// claim a UNIVERSAL over cliRuntime's 25 methods rather than a statement
// about the 3 this fixture declares. Peer of the gRPC side's
// TestShowBuffersCountingIndirectionServesNothingSilently — the two guards
// are separate because the two fixtures are separate values; a single
// shared assertion would leave whichever side it did not run on unbound.
//
// r4 embedded a concrete *dataplane.Manager, which satisfies CLI.dp
// identically AND answers the 22 undeclared methods, so a render reaching
// the backend through one of them took a load the counter could not see.
//
//   - STRUCTURAL, and this is the clause that quantifies: the embedded
//     cliRuntime must be nil. Every undeclared method promotes through
//     that one field, so nil covers all 22 without naming them.
//   - BEHAVIOURAL: IsLoaded() must panic rather than return. A panic names
//     the production line in its stack; a silent `false` names nothing.
func TestCLICountingIndirectionServesNothingSilently(t *testing.T) {
	dp := &cliCountingIndirection{backend: &cliMapStatsBackend{Manager: dataplane.New()}}

	if dp.cliRuntime != nil {
		t.Fatal("fixture drift: cliCountingIndirection embeds a non-nil cliRuntime, so the " +
			"22 methods it does not declare are SERVED rather than promoted through a nil " +
			"interface. A render reaching the backend through one of them would take a cell " +
			"load this fixture cannot count, and the grid would stay green at loads=1")
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("cliCountingIndirection.IsLoaded() returned instead of panicking: an " +
					"undeclared backend-reaching method is answerable, so the load counter's " +
					"reach is not total")
			}
		}()
		_ = dp.IsLoaded()
	}()

	if got := dp.loads.Load(); got != 0 {
		t.Fatalf("the panicking call took %d cell loads, want 0: it must not be able to "+
			"reach the backend at all", got)
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
			c := &CLI{dp: &cliCountingIndirection{backend: nil}}
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
