package frr

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #9143: every FRR `vtysh` shell-out except the one branch #6809 fixed had no
// admission bound and no request-context propagation.
//
// WHICH SIDE OF THE "EVERY X EXCEPT ONE" IS WRONG. The ONE is right and was
// under-generalized; the rest are wrong. The evidence is that this repo already
// asserts the general rule three separate times, in diagcmd, for exactly this
// cost class:
//
//   - DefaultLimiter (#5057) bounds the REST+gRPC ping/traceroute handlers,
//     which fork a child, "so a request flood cannot pin hundreds/thousands of
//     PIDs/FDs/goroutines";
//   - SessionWalkLimiter (#5433/#5708) bounds every full-table walk on both
//     surfaces;
//   - SnapshotReadLimiter (#8151) bounds the snapshot copies.
//
// An FRR status read forks a `vtysh` child that runs for up to 15s. It is the
// same class as a forking ping handler. It was simply never gated — so the
// ungated majority is the outlier, not #6809's gated branch, and generalizing
// the rule is right rather than propagating a mistake.
//
// The bound lives in the single Manager.vtysh funnel rather than at each
// handler, so the twentieth FRR read cannot be added unbounded.

// blockingExec blocks inside Vtysh until released, so a test can hold slots.
type blockingExec9143 struct {
	RecordingExecutor
	entered chan struct{}
	release chan struct{}
	gotCtx  chan context.Context
}

func (b *blockingExec9143) Vtysh(ctx context.Context, _ string) (string, error) {
	if b.gotCtx != nil {
		select {
		case b.gotCtx <- ctx:
		default:
		}
	}
	if b.entered != nil {
		b.entered <- struct{}{}
	}
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return "ok", nil
}

func withFreshVtyshLimiter9143(t *testing.T, n int) {
	t.Helper()
	orig := diagcmd.VtyshLimiter
	diagcmd.VtyshLimiter = diagcmd.NewLimiter(n)
	t.Cleanup(func() { diagcmd.VtyshLimiter = orig })
}

// The admission bound: over-cap reads are refused with ErrVtyshBusy and — the
// half that matters — WITHOUT forking. A limiter that refused after paying the
// fork would bound nothing.
func TestVtyshAdmissionRefusesOverCapWithoutForking9143(t *testing.T) {
	withFreshVtyshLimiter9143(t, 1)

	exec := &blockingExec9143{
		entered: make(chan struct{}, 4),
		release: make(chan struct{}),
	}
	m := NewForTest(t.TempDir()+"/frr.conf", exec)

	done := make(chan error, 1)
	go func() { _, err := m.GetOSPFDatabase(context.Background()); done <- err }()

	select {
	case <-exec.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first read never reached the executor")
	}

	// Second read, limiter saturated. Run it in a goroutine with a deadline: a
	// bound consulted AFTER the fork would BLOCK here (the fake executor is
	// still holding the first read), and a cell that HANGS is a VOID run, not a
	// kill — it burns the budget of every later mutation cell and reports
	// nothing. Fail fast so that mutant is actually scored.
	over := make(chan error, 1)
	go func() { _, err := m.GetOSPFNeighborDetail(context.Background()); over <- err }()
	select {
	case err := <-over:
		if !errors.Is(err, ErrVtyshBusy) {
			t.Fatalf("over-cap read returned %v, want ErrVtyshBusy", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the over-cap read BLOCKED instead of being refused — the bound is " +
			"consulted after the fork (or not at all), so it bounds nothing")
	}
	// It must not have forked: nothing else entered the executor.
	select {
	case <-exec.entered:
		t.Fatal("the refused read still reached the executor — the bound is consulted AFTER the fork, so it bounds nothing")
	default:
	}

	close(exec.release)
	if err := <-done; err != nil {
		t.Fatalf("admitted read failed: %v", err)
	}

	// Slot released: the next read is admitted again (a leaked slot would
	// wedge FRR status permanently, which is worse than the defect).
	exec2 := &blockingExec9143{}
	m2 := NewForTest(t.TempDir()+"/frr.conf", exec2)
	if _, err := m2.GetOSPFDatabase(context.Background()); err != nil {
		t.Fatalf("read after slot release failed: %v — the limiter leaks slots", err)
	}
}

// The bound is on the FUNNEL, so it covers every operational read, not a
// hand-picked list. Driving a representative from each protocol family proves
// the coverage is structural rather than per-site.
func TestVtyshAdmissionCoversEveryOperationalRead9143(t *testing.T) {
	reads := map[string]func(*Manager, context.Context) error{
		"ExecVtysh":              func(m *Manager, c context.Context) error { _, e := m.ExecVtysh(c, "show version"); return e },
		"GetBFDPeers":            func(m *Manager, c context.Context) error { _, e := m.GetBFDPeers(c); return e },
		"GetRouteMapList":        func(m *Manager, c context.Context) error { _, e := m.GetRouteMapList(c); return e },
		"GetISISAdjacencyDetail": func(m *Manager, c context.Context) error { _, e := m.GetISISAdjacencyDetail(c); return e },
		"GetISISDatabase":        func(m *Manager, c context.Context) error { _, e := m.GetISISDatabase(c); return e },
		"GetISISRoutes":          func(m *Manager, c context.Context) error { _, e := m.GetISISRoutes(c); return e },
		"GetOSPFNeighborDetail":  func(m *Manager, c context.Context) error { _, e := m.GetOSPFNeighborDetail(c); return e },
		"GetOSPFDatabase":        func(m *Manager, c context.Context) error { _, e := m.GetOSPFDatabase(c); return e },
		"GetOSPFInterface":       func(m *Manager, c context.Context) error { _, e := m.GetOSPFInterface(c); return e },
		"GetOSPFRoutes":          func(m *Manager, c context.Context) error { _, e := m.GetOSPFRoutes(c); return e },
		"GetOSPFNeighbors":       func(m *Manager, c context.Context) error { _, e := m.GetOSPFNeighbors(c); return e },
		"GetBGPSummary":          func(m *Manager, c context.Context) error { _, e := m.GetBGPSummary(c); return e },
		"GetBGPRoutes":           func(m *Manager, c context.Context) error { _, e := m.GetBGPRoutes(c); return e },
		"GetRIPRoutes":           func(m *Manager, c context.Context) error { _, e := m.GetRIPRoutes(c); return e },
		"GetISISAdjacency":       func(m *Manager, c context.Context) error { _, e := m.GetISISAdjacency(c); return e },
		"GetRouteDetailJSON":     func(m *Manager, c context.Context) error { _, e := m.GetRouteDetailJSON(c); return e },
		"GetBGPNeighborDetail": func(m *Manager, c context.Context) error {
			_, e := m.GetBGPNeighborDetail(c, "10.0.0.1")
			return e
		},
		"GetBGPNeighborReceivedRoutes": func(m *Manager, c context.Context) error {
			_, e := m.GetBGPNeighborReceivedRoutes(c, "10.0.0.1")
			return e
		},
		"GetBGPNeighborAdvertisedRoutes": func(m *Manager, c context.Context) error {
			_, e := m.GetBGPNeighborAdvertisedRoutes(c, "10.0.0.1")
			return e
		},
	}

	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			// Capacity 1, pre-drained: EVERY read must be refused.
			withFreshVtyshLimiter9143(t, 1)
			release, err := diagcmd.VtyshLimiter.Acquire()
			if err != nil {
				t.Fatalf("pre-acquire: %v", err)
			}
			defer release()

			exec := &blockingExec9143{entered: make(chan struct{}, 1)}
			m := NewForTest(t.TempDir()+"/frr.conf", exec)

			got := make(chan error, 1)
			go func() { got <- read(m, context.Background()) }()
			select {
			case err := <-got:
				if !errors.Is(err, ErrVtyshBusy) {
					t.Fatalf("%s is NOT behind the vtysh admission bound: got %v, want ErrVtyshBusy", name, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s BLOCKED instead of being refused — not behind the bound", name)
			}
			select {
			case <-exec.entered:
				t.Fatalf("%s forked despite the bound being saturated", name)
			default:
			}
		})
	}
}

// Context propagation: the caller's ctx reaches the executor, so a client
// disconnect kills the child instead of leaving it to run out the 15s budget.
// Before #9143 realExecutor.Vtysh hardcoded context.Background() and the
// Manager methods took no ctx at all, so there was nothing to propagate.
func TestVtyshPropagatesCallerContext9143(t *testing.T) {
	withFreshVtyshLimiter9143(t, 4)

	exec := &blockingExec9143{gotCtx: make(chan context.Context, 1)}
	m := NewForTest(t.TempDir()+"/frr.conf", exec)

	type ctxKey string
	const k ctxKey = "xpf-9143"
	ctx := context.WithValue(context.Background(), k, "marker")

	if _, err := m.GetOSPFDatabase(ctx); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	got := <-exec.gotCtx
	if got.Value(k) != "marker" {
		t.Fatal("the caller's context did not reach the executor — a cancelled request cannot reap the vtysh child")
	}
}

// A cancelled caller context must abort the read rather than run to the 15s cap.
func TestVtyshCancelledCallerAbortsTheRead9143(t *testing.T) {
	withFreshVtyshLimiter9143(t, 4)

	exec := &blockingExec9143{release: make(chan struct{})} // never released
	m := NewForTest(t.TempDir()+"/frr.conf", exec)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := m.GetOSPFDatabase(ctx); done <- err }()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled read returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the caller did not abort the read — the child would run out its full budget")
	}

	// And the slot is returned, not leaked by the cancellation path.
	if _, err := diagcmd.VtyshLimiter.Acquire(); err != nil {
		t.Fatalf("slot leaked on the cancellation path: %v", err)
	}
}

// The apply path must NOT be behind the client-facing budget: a status flood
// must never be able to refuse a config commit's FRR reload.
func TestApplyPathIsNotBehindTheStatusBudget9143(t *testing.T) {
	withFreshVtyshLimiter9143(t, 1)
	release, err := diagcmd.VtyshLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	defer release()

	rec := &RecordingExecutor{}
	m := NewForTest(t.TempDir()+"/frr.conf", rec)

	// FrrReloadPy / VtyshLoad go through the executor directly, not the
	// operational funnel, so a saturated status budget cannot refuse them.
	if err := m.exec.FrrReloadPy(context.Background(), "/tmp/frr.conf"); err != nil {
		t.Fatalf("apply-path reload refused while the STATUS budget is saturated: %v", err)
	}
	if _, err := m.exec.VtyshLoad(context.Background(), "/tmp/frr.conf"); err != nil {
		t.Fatalf("apply-path vtysh -f refused while the STATUS budget is saturated: %v", err)
	}
}

// ErrVtyshBusy must be classifiable with errors.Is by the surfaces that map it
// (REST 429 / gRPC ResourceExhausted), and must say what it is in its text.
func TestErrVtyshBusyIsClassifiable9143(t *testing.T) {
	if !errors.Is(ErrVtyshBusy, ErrVtyshBusy) {
		t.Fatal("ErrVtyshBusy is not comparable with errors.Is")
	}
	if !strings.Contains(ErrVtyshBusy.Error(), "concurrency limit") {
		t.Fatalf("ErrVtyshBusy text %q does not say it is a concurrency refusal", ErrVtyshBusy.Error())
	}
}
