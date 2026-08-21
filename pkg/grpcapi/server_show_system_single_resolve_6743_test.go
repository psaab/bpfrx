package grpcapi

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Codex PR #6743 r7-F3, RE-KEYED in r4-F1: the buffer renders must take
// exactly ONE load of the #2114 cell.
//
// Before r7 they took three — dataplane.Published(s.dp) (a predicate that
// no longer exists; it was `Unwrap(p) != nil` and was deleted in r2-B6),
// then s.dpProbe(), then s.dp.GetMapStats() — each an independent load. A
// setDataplane(nil) landing between them re-created the exact confusion
// that check existed to prevent: the publication check passed against a
// live backend, the later loads resolved nil, and the render printed "No
// BPF maps available" — a statement about a LOADED backend's maps — for a
// daemon that no longer had a backend at all.
//
// WHY THIS GUARD WAS RE-KEYED. The r7 version counted Unwrap CALLS and
// asserted the count was 1. That is a proxy: the property is how many
// times the render loads the cell, and not every load is an Unwrap. The
// old oneShotIndirection embedded *dataplane.Manager and declared only
// Unwrap, so `s.dp.SessionCount()` — which under the real liveDataPlane
// calls resolve(), an independent load — was served by the embedded
// Manager and never touched the counter. The guard therefore stayed green
// across a residual second load that lived in the very arm its own fixture
// drove (mapStatsBackend has no Status(), so the map-stats arm is the one
// exercised). Measured at 6163445e9: reverting BOTH userspace-arm
// conversions left ./pkg/grpcapi/... ./pkg/cli/... ./pkg/api/...
// ./pkg/dataplane/... AND ./pkg/daemon/... at rc=0 — a complete survivor.
//
// The fixture below is keyed on the property instead. Its reach is TOTAL
// over grpcRuntime's 25 methods, and that is a property of how it is
// built rather than of how many methods it happens to declare:
//
//   - the three methods declared below (Unwrap, SessionCount, GetMapStats)
//     each perform their OWN counted cell load, exactly as liveDataPlane
//     does — Unwrap reads d.dataplane(); resolve() reads it again;
//   - EVERY OTHER method PANICS, because the embedded grpcRuntime is a nil
//     interface. Method promotion dispatches all 22 undeclared methods
//     through that field, so none of them can quietly answer.
//
// There is therefore no method on this value that reaches the backend
// without the counter seeing it. That is the r4 correction: r4 embedded a
// concrete *dataplane.Manager, which SERVED those 22 — closing 2 of 25
// while the header claimed all of them. Measured at 44603f888: inserting
// `if !s.dp.IsLoaded() { buf.WriteString("stale\n") }` into showBuffers'
// map-stats arm — a real second cell load — left loads=1, all four
// subtests PASS, pkg/grpcapi rc=0. Bound now by
// TestShowBuffersCountingIndirectionServesNothingSilently.
//
// A render that takes a second load through a DECLARED method both bumps
// the counter AND observably tears, because the cell is empty from load 2
// onward. That is deterministic, not a race: a cell that holds a backend
// at load 1 and nothing afterwards is the observable consequence of a
// concurrent setDataplane(nil) with the timing removed.

const (
	// The published backend's session counts. Non-zero on BOTH families so
	// the render's `if v4 > 0 || v6 > 0` gate opens: a second load resolves
	// nil, yields (0,0), and the "Active sessions" line vanishes. A zero
	// count here would suppress the line either way and make the output
	// assertion vacuous — which is what the r7 fixture did.
	singleLoadV4 = 7
	singleLoadV6 = 3
)

// singleLoadActiveSessions is the operator-visible consequence of taking
// exactly one load. Under two loads this line is silently absent.
const singleLoadActiveSessions = "Active sessions: 7 IPv4, 3 IPv6, 10 total"

// countingIndirection is a live indirection modelled on pkg/daemon's
// liveDataPlane: a backend-reaching method performs its OWN cell load, and
// the cell is empty from the second load onward.
//
// The embedded grpcRuntime is a nil INTERFACE, never a concrete value. It
// is what makes this value assignable to Server.dp — the promoted method
// set is grpcRuntime's, so *countingIndirection satisfies the field — and
// it is simultaneously what makes the counter's reach total: the three
// methods below shadow their promoted counterparts, and every OTHER
// promoted method dispatches through a nil interface and panics at the
// production call site that took it.
//
// Do NOT restore the r4 `*dataplane.Manager` embed. A concrete embed
// satisfies the same field while SERVING the 22 undeclared methods, so a
// render that reached the backend through any of them took a cell load
// this fixture could not see, and the counter stayed at 1. A loud panic
// naming the production line is the intended answer; a silent zero is the
// bug. TestShowBuffersCountingIndirectionServesNothingSilently binds it.
type countingIndirection struct {
	grpcRuntime
	backend any
	loads   atomic.Int32
}

// load is the single counted cell read. Every forwarder goes through it,
// which is what makes the count a count of LOADS rather than of Unwraps.
func (o *countingIndirection) load() any {
	if o.loads.Add(1) == 1 {
		return o.backend
	}
	return nil
}

func (o *countingIndirection) Unwrap() any { return o.load() }

// SessionCount mirrors liveDataPlane.SessionCount, which resolves the cell
// itself. This is the method the r7 guard could not see.
func (o *countingIndirection) SessionCount() (int, int) {
	c, ok := o.load().(interface{ SessionCount() (int, int) })
	if !ok {
		return 0, 0
	}
	return c.SessionCount()
}

// GetMapStats mirrors liveDataPlane.GetMapStats for the same reason.
func (o *countingIndirection) GetMapStats() []dataplane.MapStats {
	m, ok := o.load().(interface{ GetMapStats() []dataplane.MapStats })
	if !ok {
		return nil
	}
	return m.GetMapStats()
}

var (
	_ dataplane.LiveUnwrapper = (*countingIndirection)(nil)
	// The nil embed is what makes the fixture storable in Server.dp. If
	// this assertion ever needs a concrete embed to hold, the counter has
	// lost its reach — see the type's doc comment.
	_ grpcRuntime = (*countingIndirection)(nil)
)

// mapStatsBackend drives the MAP-STATS arm: no userspace Status() probe,
// and a non-empty map list so "No BPF maps available" can only mean the
// render lost the backend.
type mapStatsBackend struct {
	*dataplane.Manager
}

func (*mapStatsBackend) IsLoaded() bool { return true }

func (*mapStatsBackend) SessionCount() (int, int) {
	return singleLoadV4, singleLoadV6
}

func (*mapStatsBackend) GetMapStats() []dataplane.MapStats {
	return []dataplane.MapStats{{
		Name:       "sessions_v4",
		Type:       "Hash",
		MaxEntries: 1024,
		UsedCount:  4,
	}}
}

// userspaceArmBackend drives the USERSPACE arm — the arm this PR's own
// diff converted. Without a row here the conversion is unbound: a reviewer
// measured both userspace-arm reverts as complete survivors precisely
// because the shipped fixture never entered this arm.
type userspaceArmBackend struct {
	*dataplane.Manager
}

func (*userspaceArmBackend) IsLoaded() bool { return true }

func (*userspaceArmBackend) SessionCount() (int, int) {
	return singleLoadV4, singleLoadV6
}

func (*userspaceArmBackend) Status() (dpuserspace.ProcessStatus, error) {
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

// singleLoadArms are the two capability shapes the renders branch on. Both
// must take one load; the arm names below appear in every failure message
// so a red says WHICH branch tore.
var singleLoadArms = []struct {
	name    string
	backend func() any
	// wantMarker is a string unique to this arm's body, so a green cannot
	// come from the render having silently taken the other branch.
	wantMarker string
}{
	{
		name:       "mapStatsArm",
		backend:    func() any { return &mapStatsBackend{Manager: dataplane.New()} },
		wantMarker: "sessions_v4",
	},
	{
		name:       "userspaceArm",
		backend:    func() any { return &userspaceArmBackend{Manager: dataplane.New()} },
		wantMarker: "Userspace Buffer Utilization:",
	},
}

var singleLoadRenders = []struct {
	name   string
	render func(*Server, *config.Config, *strings.Builder) error
}{
	{"showBuffers", (*Server).showBuffers},
	{"showBuffersDetail", (*Server).showBuffersDetail},
}

// TestShowBuffersTakesOneCellLoad is the fail-on-revert guard, over the
// full render x arm grid.
//
// FAIL-ON-REVERT, per arm:
//
//   - map-stats arm: restore `v4, v6 := s.dp.SessionCount()` in place of
//     backendSessionCount(backend) at the tail of the else-branch. Load 2
//     resolves the emptied cell, SessionCount returns (0,0), and the
//     "Active sessions" line disappears — loads=2 and the marker assertion
//     both go RED.
//   - userspace arm: the same substitution inside the
//     `if provider, ok := backend.(userspaceStatusProvider)` branch, which
//     is the line this PR's diff created. Same two REDs.
//
// A three-load revert (a publication check that resolves the cell itself,
// then dpProbe(), then GetMapStats()) reds on the arm marker as well: the
// map arm falls to "No BPF maps available", which the explicit check below
// names.
func TestShowBuffersTakesOneCellLoad(t *testing.T) {
	for _, render := range singleLoadRenders {
		for _, arm := range singleLoadArms {
			t.Run(render.name+"/"+arm.name, func(t *testing.T) {
				dp := &countingIndirection{backend: arm.backend()}
				s := &Server{
					dp:    dp,
					store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
				}

				var buf strings.Builder
				if err := render.render(s, &config.Config{}, &buf); err != nil {
					t.Fatalf("%s/%s: %v", render.name, arm.name, err)
				}
				out := buf.String()

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

				// The operator-visible consequence. A second load resolves
				// the emptied cell, SessionCount yields (0,0), and the
				// render's `if v4 > 0 || v6 > 0` gate silently drops this
				// line: one render describing two instants, reported as
				// though the firewall simply had no sessions.
				if !strings.Contains(out, singleLoadActiveSessions) {
					t.Fatalf("%s/%s dropped the session-count line (loads=%d): want %q. "+
						"The tail must read backendSessionCount(backend), not "+
						"s.dp.SessionCount() — the latter loads the cell a second time "+
						"and reports (0,0) against the emptied cell.\n%s",
						render.name, arm.name, dp.loads.Load(), singleLoadActiveSessions, out)
				}

				// The property itself.
				if got := dp.loads.Load(); got != 1 {
					t.Fatalf("%s/%s loaded the cell %d times, want exactly 1",
						render.name, arm.name, got)
				}
			})
		}
	}
}

// TestShowBuffersCountingIndirectionErasesCapabilities is fixture fidelity.
//
// countingIndirection must NOT itself satisfy userspaceStatusProvider, or
// the userspace-arm row above would pass without any unwrap at all and the
// grid would be vacuous in the arm this PR changed.
func TestShowBuffersCountingIndirectionErasesCapabilities(t *testing.T) {
	dp := &countingIndirection{backend: &userspaceArmBackend{Manager: dataplane.New()}}
	if _, ok := any(dp).(userspaceStatusProvider); ok {
		t.Fatal("fixture drift: countingIndirection implements userspaceStatusProvider " +
			"directly, so the userspace-arm rows no longer exercise a resolution")
	}
	if dp.loads.Load() != 0 {
		t.Fatalf("fixture drift: constructing countingIndirection loaded the cell %d times, want 0",
			dp.loads.Load())
	}
}

// TestShowBuffersCountingIndirectionServesNothingSilently is what makes
// the grid's claim a UNIVERSAL over grpcRuntime's 25 methods rather than a
// statement about the 3 this fixture declares.
//
// r4 embedded a concrete *dataplane.Manager. That satisfies Server.dp
// identically, and it ALSO answers the 22 methods the fixture does not
// declare — so a render reaching the backend through any of them took a
// cell load the counter could not see, and the grid stayed green at
// loads=1. The r4 fixture closed 2 of 25 while its header said EVERY.
//
// Two clauses, because they say different things:
//
//   - STRUCTURAL, and this is the one that quantifies: the embedded
//     grpcRuntime must be nil. Go promotes every undeclared method through
//     that one field, so nil covers all 22 at once without naming them —
//     an enumeration here would be the same mistake in a new place.
//   - BEHAVIOURAL: IsLoaded() — the method a reviewer actually inserted
//     into showBuffers' map-stats arm at 44603f888 and measured green —
//     must panic rather than return. A panic names the production line in
//     its stack; a silent `false` names nothing.
func TestShowBuffersCountingIndirectionServesNothingSilently(t *testing.T) {
	dp := &countingIndirection{backend: &mapStatsBackend{Manager: dataplane.New()}}

	if dp.grpcRuntime != nil {
		t.Fatal("fixture drift: countingIndirection embeds a non-nil grpcRuntime, so the " +
			"22 methods it does not declare are SERVED rather than promoted through a nil " +
			"interface. A render reaching the backend through one of them would take a cell " +
			"load this fixture cannot count, and the grid would stay green at loads=1 — " +
			"which is exactly how the r4 *dataplane.Manager embed closed 2 of 25 methods " +
			"while claiming all of them")
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("countingIndirection.IsLoaded() returned instead of panicking: an " +
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

// TestShowBuffersEmptyCellSaysNotLoaded is the negative control: with NO
// backend at all the render must still say "Dataplane not loaded", so the
// grid above cannot pass merely because the "No BPF maps available" string
// was deleted.
func TestShowBuffersEmptyCellSaysNotLoaded(t *testing.T) {
	dp := &countingIndirection{backend: nil}
	s := &Server{
		dp:    dp,
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	var buf strings.Builder
	if err := s.showBuffers(&config.Config{}, &buf); err != nil {
		t.Fatalf("showBuffers: %v", err)
	}
	if !strings.Contains(buf.String(), "Dataplane not loaded") {
		t.Fatalf("empty cell must render \"Dataplane not loaded\", got:\n%s", buf.String())
	}
}
