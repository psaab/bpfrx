package cli

import (
	"reflect"
	"sort"
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
// it again). Its reach is TOTAL over cliRuntime's method set, and by
// construction rather than by count:
//
//   - the three declared below (Unwrap, SessionCount, GetMapStats) each
//     take their own counted load;
//   - EVERY OTHER method PANICS, because the embedded cliRuntime is a nil
//     interface and promotion dispatches every undeclared method through
//     that one field. None of them can quietly answer.
//
// That is the r4 correction: r4 embedded a concrete *dataplane.Manager,
// which SERVED all the rest — closing 2 of 25 while the header claimed all
// of them.
//
// The undeclared-method count is NOT written down here, deliberately: two
// rounds carried a hand-typed "22" against a 25-method interface with 2
// shadows, which is 23. TestCLICountingIndirectionServesNothingSilently
// derives both the population and the partition from the interface TYPE,
// so the claim is checked at every run instead of restated in prose.
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
// Do NOT restore the r4 `*dataplane.Manager` embed, and do not populate
// this field at a construction site either — r6 measured that spelling as
// the live escape. A non-nil embed satisfies the same field while SERVING
// every undeclared method, so a render reaching the backend through any of
// them takes a load this fixture cannot see — which is exactly how the
// gRPC peer's guard went blind. load() refuses a populated embed and
// TestCLICountingIndirectionServesNothingSilently proves that refusal
// fires.
type cliCountingIndirection struct {
	cliRuntime
	backend any
	loads   atomic.Int32
}

// load is the single counted cell read, and — #6743 r6-B1 — the place the
// nil-embed invariant is ENFORCED rather than merely asserted about.
//
// r5 put the assertion inside TestCLICountingIndirectionServesNothingSilently,
// on a value that test constructed with the embed omitted from the literal:
// the zero value of an interface field, nil unconditionally. The clause was
// a tautology over the only value it inspected, and the value that matters
// — the one the grid stores in CLI.dp — was never looked at. Measured at
// 74ece3ff5: `&cliCountingIndirection{cliRuntime: dataplane.New(), backend:
// arm.backend()}` in the grid, plus the r4 witness (`if !c.dp.IsLoaded()`)
// back in both map-stats arms, left the whole of pkg/cli at rc=0.
//
// load() is the choke point every counted method already goes through, so
// a check here holds for EVERY instance a render touches, at every
// construction site, present or future.
func (a *cliCountingIndirection) load() any {
	if a.cliRuntime != nil {
		panic("cliCountingIndirection: the embedded cliRuntime is NON-NIL, so the methods " +
			"this fixture does not declare are SERVED rather than promoted through a nil " +
			"interface. A render reaching the backend through one of them takes a cell load " +
			"the counter cannot see, and the grid stays green at loads=1 — the r4 defect. " +
			"Build this fixture with the embed left nil.")
	}
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

// The Unwrap contract is NOT compile-checked anywhere else: the render
// reaches it through dataplane.Unwrap's runtime type assertion, so a
// rename would surface as a silent "not loaded" render rather than as a
// build error.
//
// #6743 r6-B4: the sibling `_ cliRuntime = (*cliCountingIndirection)(nil)`
// assertion that stood here was deleted. It could not fail on its own —
// the grid stores the fixture in CLI.dp, which is typed cliRuntime, so the
// compiler already made exactly that check at a site the tests exercise.
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

// cliPartitionRuntimeMethods calls EVERY method of interface type iface on
// dp with zero-value arguments and reports which answered and which
// panicked. Peer of pkg/grpcapi's partitionRuntimeMethods; the two are
// separate because the two packages are, and a shared helper would have to
// live somewhere neither test owns.
//
// The population comes from the interface TYPE, so the universal is
// measured rather than counted into a comment. Zero-value arguments are
// safe on the correct fixture: dispatch through a nil embedded interface
// panics BEFORE any callee runs, so no argument is examined.
func cliPartitionRuntimeMethods(t *testing.T, dp any, iface reflect.Type) (served, panicked []string) {
	t.Helper()

	v := reflect.ValueOf(dp)
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		m := v.MethodByName(name)
		if !m.IsValid() {
			t.Fatalf("fixture drift: %T has no method %s, so it no longer satisfies the "+
				"runtime interface this guard quantifies over", dp, name)
		}
		args := make([]reflect.Value, m.Type().NumIn())
		for j := range args {
			args[j] = reflect.New(m.Type().In(j)).Elem()
		}
		func() {
			defer func() {
				if recover() != nil {
					panicked = append(panicked, name)
				}
			}()
			m.Call(args)
			served = append(served, name)
		}()
	}
	sort.Strings(served)
	sort.Strings(panicked)
	return served, panicked
}

// cliCountingIndirectionShadows are the cliRuntime methods
// cliCountingIndirection DECLARES, and so answers itself with a counted
// load. Every other method of the interface must be unanswerable.
var cliCountingIndirectionShadows = []string{"GetMapStats", "SessionCount"}

// TestCLICountingIndirectionServesNothingSilently is what makes the grid's
// claim a UNIVERSAL over cliRuntime's whole method set rather than a
// statement about the 3 this fixture declares. Peer of the gRPC side's
// TestShowBuffersCountingIndirectionServesNothingSilently — the two guards
// are separate because the two fixtures are separate values; a single
// shared assertion would leave whichever side it did not run on unbound.
//
// r4 embedded a concrete *dataplane.Manager, which satisfies CLI.dp
// identically AND answers every undeclared method, so a render reaching
// the backend through one of them took a load the counter could not see.
//
// #6743 r6-B1 — what changed:
//
//   - r5's structural clause read `dp.cliRuntime != nil` on a fixture THIS
//     TEST built with the embed omitted, so it was a tautology over an
//     interface field's zero value. The grid's fixture — the one stored in
//     CLI.dp — was never inspected. Measured at 74ece3ff5: populating the
//     grid's literal restored the r4 second-load defect with every guard
//     green and pkg/cli at rc=0.
//   - The invariant now lives in load(), the choke point.
//   - r5's behavioural clause sampled ONE method. This one partitions the
//     ENTIRE interface method set, read from the type by reflection.
//
// The POSITIVE CONTROL builds the defective fixture on purpose and proves
// both halves of the mechanism: that a populated embed really does SERVE
// an undeclared method silently, and that load() really does refuse it.
func TestCLICountingIndirectionServesNothingSilently(t *testing.T) {
	iface := reflect.TypeOf((*cliRuntime)(nil)).Elem()

	served, panicked := cliPartitionRuntimeMethods(t,
		&cliCountingIndirection{backend: &cliMapStatsBackend{Manager: dataplane.New()}}, iface)

	if !reflect.DeepEqual(served, cliCountingIndirectionShadows) {
		t.Fatalf("methods answered by cliCountingIndirection = %v, want exactly %v.\n"+
			"Anything else answering means an undeclared method is SERVED rather than "+
			"promoted through a nil interface, so a render could reach the backend through "+
			"it and take a cell load the counter cannot see — the r4 defect. Anything "+
			"MISSING means a declared forwarder started panicking.\npanicked: %v",
			served, cliCountingIndirectionShadows, panicked)
	}
	if want := iface.NumMethod() - len(cliCountingIndirectionShadows); len(panicked) != want {
		t.Fatalf("%d of cliRuntime's %d methods panicked, want %d: the counter's reach is "+
			"total only if every method this fixture does not declare is unanswerable\n%v",
			len(panicked), iface.NumMethod(), want, panicked)
	}

	defective := &cliCountingIndirection{
		cliRuntime: dataplane.New(),
		backend:    &cliMapStatsBackend{Manager: dataplane.New()},
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("control: IsLoaded() on a POPULATED embed panicked (%v); the "+
					"defect this guard exists to catch is that the embed answers "+
					"SILENTLY, so if it cannot answer, the guard is passing for the "+
					"wrong reason", r)
			}
		}()
		_ = defective.IsLoaded()
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("control: load() accepted a fixture with a POPULATED embed. The " +
					"invariant is not enforced at the choke point, so a grid that builds " +
					"its fixture that way counts one load while the render takes two — " +
					"which is the escape measured at 74ece3ff5")
			}
		}()
		_ = defective.Unwrap()
	}()
	// A refusal that counts first is not a refusal: moving the guard below
	// loads.Add(1) would leave the panic in place — so the clause above
	// still passes — while polluting the very number the grid asserts on.
	if got := defective.loads.Load(); got != 0 {
		t.Fatalf("control: the refused load still bumped the counter to %d, want 0: the "+
			"embed check must run BEFORE loads.Add(1)", got)
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
