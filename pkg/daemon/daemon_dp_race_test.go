package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"golang.org/x/sync/semaphore"
)

// #2114 dataplane-cell regression tests (plan §9 item 2). Run under
// `go test -race` via the test-race-dp target. The cell makes the
// publication race-free; these tests pin that against the REAL writer
// paths (bootstrap-exit arm, boot publication) with reader shapes drawn
// from the §5.4 reader audit — and several are two-sided gates with NO
// happens-before edge between the conflicting accesses, so on a revert to
// the plain interface field the race detector fires deterministically (the
// ABSENCE of the HB edge is a memory-model proposition, not a timing one).

// ---------------------------------------------------------------------------
// Shared fakes.
// ---------------------------------------------------------------------------

// cellValueDP is a value-receiver RuntimeDataPlane for the value-kind cell
// leg (a non-nillable concrete value must Store normally, never panic).
type cellValueDP struct{}

func (cellValueDP) Start(context.Context) error { return nil }
func (cellValueDP) Close() error                { return nil }
func (cellValueDP) Teardown() error             { return nil }
func (cellValueDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return nil, nil
}
func (cellValueDP) LastApplyResult() *dataplane.ApplyResult { return nil }
func (cellValueDP) Link() dataplane.LinkController          { return nil }
func (cellValueDP) HA() dataplane.HAController              { return nil }
func (cellValueDP) Sessions() dataplane.SessionStore        { return nil }
func (cellValueDP) Telemetry() dataplane.Telemetry          { return nil }
func (cellValueDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

// Named nillable kinds carrying the RuntimeDataPlane method set — the
// kind-gated typed-nil guard must Store each typed-nil of these as nil
// without panicking (reflect.Value.IsNil panics on non-nillable kinds;
// named Chan/Func/Map/Slice types can carry methods — the in-repo
// precedent is pkg/dataplane/userspace/wire_uint8list.go).
type cellNilSliceDP []byte
type cellNilMapDP map[string]int
type cellNilChanDP chan int
type cellNilFuncDP func()

func (cellNilSliceDP) Start(context.Context) error { return nil }
func (cellNilSliceDP) Close() error                { return nil }
func (cellNilSliceDP) Teardown() error             { return nil }
func (cellNilSliceDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return nil, nil
}
func (cellNilSliceDP) LastApplyResult() *dataplane.ApplyResult { return nil }
func (cellNilSliceDP) Link() dataplane.LinkController          { return nil }
func (cellNilSliceDP) HA() dataplane.HAController              { return nil }
func (cellNilSliceDP) Sessions() dataplane.SessionStore        { return nil }
func (cellNilSliceDP) Telemetry() dataplane.Telemetry          { return nil }
func (cellNilSliceDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (cellNilMapDP) Start(context.Context) error { return nil }
func (cellNilMapDP) Close() error                { return nil }
func (cellNilMapDP) Teardown() error             { return nil }
func (cellNilMapDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return nil, nil
}
func (cellNilMapDP) LastApplyResult() *dataplane.ApplyResult { return nil }
func (cellNilMapDP) Link() dataplane.LinkController          { return nil }
func (cellNilMapDP) HA() dataplane.HAController              { return nil }
func (cellNilMapDP) Sessions() dataplane.SessionStore        { return nil }
func (cellNilMapDP) Telemetry() dataplane.Telemetry          { return nil }
func (cellNilMapDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (cellNilChanDP) Start(context.Context) error { return nil }
func (cellNilChanDP) Close() error                { return nil }
func (cellNilChanDP) Teardown() error             { return nil }
func (cellNilChanDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return nil, nil
}
func (cellNilChanDP) LastApplyResult() *dataplane.ApplyResult { return nil }
func (cellNilChanDP) Link() dataplane.LinkController          { return nil }
func (cellNilChanDP) HA() dataplane.HAController              { return nil }
func (cellNilChanDP) Sessions() dataplane.SessionStore        { return nil }
func (cellNilChanDP) Telemetry() dataplane.Telemetry          { return nil }
func (cellNilChanDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (cellNilFuncDP) Start(context.Context) error { return nil }
func (cellNilFuncDP) Close() error                { return nil }
func (cellNilFuncDP) Teardown() error             { return nil }
func (cellNilFuncDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return nil, nil
}
func (cellNilFuncDP) LastApplyResult() *dataplane.ApplyResult { return nil }
func (cellNilFuncDP) Link() dataplane.LinkController          { return nil }
func (cellNilFuncDP) HA() dataplane.HAController              { return nil }
func (cellNilFuncDP) Sessions() dataplane.SessionStore        { return nil }
func (cellNilFuncDP) Telemetry() dataplane.Telemetry          { return nil }
func (cellNilFuncDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

// TestRuntimeDataplaneNeverBareRootManager pins the dead-surface
// property the #2114 A3 Compile-continuation waiver rests on (Codex PR
// #6743 r2-6): the daemon's runtime dataplane is NEVER the bare root
// *dataplane.Manager — it is the userspace adapter — so the root
// Manager.Compile (compiler.go) is unreachable in production and its
// absent-redirect_capable continuation is a dead-surface property. If
// this ever fails, the root Compile is live again and compiler.go:353's
// continuation needs a real discriminating leg before merge.
func TestRuntimeDataplaneNeverBareRootManager(t *testing.T) {
	dp, err := buildRuntimeDataPlane("")
	if err != nil {
		t.Fatalf("buildRuntimeDataPlane: %v", err)
	}
	if _, bare := dp.(*dataplane.Manager); bare {
		t.Fatal("the daemon's runtime dataplane is the bare root *dataplane.Manager")
	}
	if _, ok := dp.(interface {
		Manager() *dpuserspace.Manager
	}); !ok {
		t.Fatalf("runtime dataplane = %T, want the userspace adapter (Manager() probe)", dp)
	}
}

// failingStartUserspaceDP is the bootstrap-exit arm-failure fake: Start
// invokes the optional barrier hook and then fails; the CachedStatus probe
// keeps it on the userspace adapter path so the forwarding-status sampler
// exercises the full read chain against it.
type failingStartUserspaceDP struct {
	runtimeOnlyApplyTestDP
	onStart func()
}

func (f *failingStartUserspaceDP) Start(context.Context) error {
	if f.onStart != nil {
		f.onStart()
	}
	return errors.New("synthetic arm failure (#2114 test)")
}

func (f *failingStartUserspaceDP) CachedStatus() (dpuserspace.ProcessStatus, bool) {
	return dpuserspace.ProcessStatus{}, false
}

// dataplaneCellReaderChurn is a running set of reader goroutines plus the
// rendezvous channels the callers need.
//
// `ready` closes once every shape has completed one pass. Codex PR #6743
// r6-F6 corrected the claim r4 made for it: a completed first pass proves
// the readers are RUNNING before the writer starts — it does NOT prove any
// read happens once the writer is under way. A legal schedule parks every
// reader immediately after its first pass, runs the writer to completion,
// closes stop, and lets the readers exit: `ready` is satisfied and not one
// unordered read overlapped a write.
//
// `round()` supplies the missing half. It opens a fresh per-shape
// rendezvous: the returned channel closes only after EVERY shape has
// completed a pass that BEGAN after the round was opened. A caller that
// opens a round while the writer is parked mid-write, and another after
// the write has landed, has PROVEN reader activity on both sides of the
// write instead of assuming it — the same bracketing
// TestDataplaneCell_ClusterStartPublication uses around its publication.
//
// WHAT THE BRACKETING PROVES, AND WHAT IT DOES NOT (Codex PR #6743
// r7-F2). It proves LIVENESS, and for a SINGLE-SHOT writer that is all it
// proves: the round is itself a happens-before edge in BOTH directions.
// A reader's wg.Done() -> the helper's Wait() -> close(ch) -> the caller's
// <-ch orders every credited pass BEFORE the store; the caller's next
// cur.Store(round) -> a reader's cur.Load() orders every subsequently
// credited pass AFTER it. The only unordered pairs left are UNCREDITED
// passes between a reader's wg.Done() and its next Load(), and nothing
// forces one to exist.
//
// That is not a theoretical worry — it was MEASURED, against a plain-field
// shadow of the cell (dpCell replaced by a plain interface field, the
// revert these tests exist to catch), under -race:
//
//	                                       GOMAXPROCS=1   default
//	BootstrapExit_ArmFailureWithConcurrentReaders   0/5      2/2
//	DataplaneCell_RollbackRearmRecurrence           0/5      fires
//	BootstrapExit_RealSamplerOverlap  (control)     3/3      fires
//	DataplaneCell_ConcurrentReadersVsWriter (ctrl)  2/3      fires
//
// The controls prove GOMAXPROCS=1 does not blind the detector; the zero
// cells are PASSes, not skips. ConcurrentReadersVsWriter is not a
// single-shot writer — it stores CONTINUOUSLY while the round is open —
// which is why it still fires.
//
// So the REVERT-FIRES property for the two single-shot bootstrap-exit
// writers is carried by the deterministic two-sided gates, NOT by the
// bracketing: TestBootstrapExit_RealSamplerOverlap for the arm-failure
// store and TestDataplaneCell_RollbackRearmOverlap for the rollback +
// re-arm store. Both park reader and writer immediately before their
// conflicting accesses and release them with one close, so neither side
// is ordered with respect to the other. The bracketed tests remain
// valuable for what they do assert — the real writer paths, the cell/
// monitor postconditions, and the retention identity contract — and for
// proving those assertions were made with readers provably live.
type dataplaneCellReaderChurn struct {
	ready chan struct{}
	done  chan struct{}

	// cur is the open round, or nil. Readers snapshot it BEFORE each pass
	// so a pass credited to a round provably started after the round was
	// opened.
	cur atomic.Pointer[readerRound]
}

// readerRound is one "every shape has made a fresh pass" rendezvous.
type readerRound struct {
	wg sync.WaitGroup
	ch chan struct{}
}

// round opens a new rendezvous and returns its completion channel.
func (c *dataplaneCellReaderChurn) round(shapes int) <-chan struct{} {
	r := &readerRound{ch: make(chan struct{})}
	r.wg.Add(shapes)
	c.cur.Store(r)
	go func() { r.wg.Wait(); close(r.ch) }()
	return r.ch
}

// awaitReaderRound opens a round and blocks until every shape has made a
// pass inside it. A timeout is an ASSERTION failure, not a hang: it means
// the overlap the caller is about to claim did not happen.
func awaitReaderRound(t *testing.T, churn *dataplaneCellReaderChurn, what string) {
	t.Helper()
	select {
	case <-churn.round(dataplaneCellReaderShapes):
	case <-time.After(30 * time.Second):
		t.Errorf("no reader pass completed %s: the overlap this test claims to "+
			"exercise did not happen, so a green run says nothing about the cell", what)
	}
}

// dataplaneCellReaderShapes is the number of reader shapes
// churnDataplaneCellReaders runs. It is a constant so a round can be sized
// without reaching into the closure; churnDataplaneCellReaders panics if
// the two ever diverge.
const dataplaneCellReaderShapes = 5

// churnDataplaneCellReaders launches the §5.4 reader shapes against the
// cell until stop closes: the narrowed forwarding-status adapter
// CachedStatus probe, applyResult(), a PolicySchedulerActiveStateFn-shape
// probe, the NAT pool sampler closure, and a watchdog-shape per-tick load
// (one load per tick, shared across a small RG loop).
//
// The returned churn's ready channel closes once EVERY shape has made a
// pass; done closes once every shape has returned after stop.
func churnDataplaneCellReaders(d *Daemon, stop <-chan struct{}) *dataplaneCellReaderChurn {
	churn := &dataplaneCellReaderChurn{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
	var wg sync.WaitGroup
	adapter := d.forwardingStatusDataplane()
	sampler := d.natPoolAlarmSampler()
	shapes := []func(){
		func() {
			if adapter != nil {
				_, _ = adapter.CachedStatus()
			}
		},
		func() { _ = d.applyResult() },
		func() {
			rt := d.dataplane()
			if rt == nil {
				return
			}
			if p, ok := rt.(interface {
				PolicySchedulerActiveState() map[string]bool
			}); ok {
				_ = p.PolicySchedulerActiveState()
			}
		},
		func() { _ = sampler() },
		func() {
			// watchdog shape: one load per tick shared across the RG loop
			rt := d.dataplane()
			if rt == nil {
				return
			}
			for _, rg := range []int{0, 1} {
				_ = rt.HA().SetRGActive(context.Background(), rg, true)
			}
		},
	}
	if len(shapes) != dataplaneCellReaderShapes {
		panic("dataplaneCellReaderShapes out of sync with the shape list")
	}
	var firstPass sync.WaitGroup
	firstPass.Add(len(shapes))
	for _, shape := range shapes {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			// One pass BEFORE signalling ready, so the caller's writer
			// cannot start against a set of not-yet-scheduled readers.
			fn()
			firstPass.Done()
			var credited *readerRound
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Snapshot the open round BEFORE the pass: a pass credited
				// below therefore provably began after that round opened.
				r := churn.cur.Load()
				fn()
				if r != nil && r != credited {
					credited = r
					r.wg.Done()
				}
			}
		}(shape)
	}
	go func() { firstPass.Wait(); close(churn.ready) }()
	go func() { wg.Wait(); close(churn.done) }()
	return churn
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

// TestDataplaneCell_ConcurrentReadersVsWriter hammers the accessor-routed
// readers while a writer alternates setDataplane(nil)/setDataplane(fake).
// Revert-guard: on the plain interface field this is the RACE-2 schedule
// and the detector fires.
//
// r6-F6: the overlap is now PROVEN rather than assumed. The writer keeps
// storing until a full round of reader passes has completed INSIDE the
// write loop, so at least one pass per shape provably began after the
// writer started and finished before it stopped.
func TestDataplaneCell_ConcurrentReadersVsWriter(t *testing.T) {
	d := &Daemon{}
	stop := make(chan struct{})
	churn := churnDataplaneCellReaders(d, stop)
	<-churn.ready // every shape has run at least once

	// Open the overlap round FIRST, then write until it closes: every
	// credited pass began after this point, i.e. inside the write loop.
	overlap := churn.round(dataplaneCellReaderShapes)
	soft := time.Now().Add(300 * time.Millisecond)
	hard := time.Now().Add(30 * time.Second)
	overlapped := false
	for {
		d.setDataplane(nil)
		d.setDataplane(&runtimeOnlyApplyTestDP{})
		if !overlapped {
			select {
			case <-overlap:
				overlapped = true
			default:
			}
			if !overlapped && time.Now().After(hard) {
				t.Fatal("no reader shape completed a pass inside the write loop: the " +
					"reader/writer overlap this test claims to exercise did not happen")
			}
			continue
		}
		if time.Now().After(soft) {
			break
		}
	}
	close(stop)
	<-churn.done
}

// TestDataplaneCell_TypedNilAndValueShapes is the kind-gated guard matrix:
// a typed-nil of EVERY nillable kind Stores as nil; a value-type
// implementation Stores normally (no panic, non-nil read back).
func TestDataplaneCell_TypedNilAndValueShapes(t *testing.T) {
	var nilPtr *cellValueDP
	var nilSlice cellNilSliceDP
	var nilMap cellNilMapDP
	var nilChan cellNilChanDP
	var nilFunc cellNilFuncDP

	cases := []struct {
		name  string
		value dataplane.RuntimeDataPlane
		wantN bool // want d.dataplane() == nil after the Store
	}{
		{"typed-nil pointer", nilPtr, true},
		{"typed-nil named slice", nilSlice, true},
		{"typed-nil named map", nilMap, true},
		{"typed-nil named chan", nilChan, true},
		{"typed-nil named func", nilFunc, true},
		{"value type stores normally", cellValueDP{}, false},
		{"pointer value stores normally", &cellValueDP{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{}
			d.setDataplane(tc.value)
			if got := d.dataplane(); (got == nil) != tc.wantN {
				t.Fatalf("dataplane() nil=%v, want nil=%v", got == nil, tc.wantN)
			}
		})
	}
}

// TestForwardingStatusAdapter_BackendTypeTransitions proves per-call
// capability adaptation across the three backend shapes (plan §9): a
// readyProbeOnly fake (no CachedStatus — adapter reports ok=false) → a
// userspace fake (ok=true, injected status) → nil (ok=false). The pre-#2114
// construction-time wrapper selection could not express the middle leg: a
// base wrapper permanently lacked CachedStatus and a nil-at-construction
// accessor never gained it.
func TestForwardingStatusAdapter_BackendTypeTransitions(t *testing.T) {
	d := &Daemon{}
	d.setDataplane(&forwardingStatusDaemonTestDP{}) // no CachedStatus probe

	provider := d.forwardingStatusDataplane()
	if provider == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if _, ok := provider.CachedStatus(); ok {
		t.Fatal("CachedStatus() ok=true for a readyProbeOnly backend, want false")
	}

	d.setDataplane(&forwardingStatusDaemonUserspaceTestDP{
		forwardingStatusDaemonTestDP: &forwardingStatusDaemonTestDP{},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{ThreadCPUNS: 42, WallNS: 84}},
		},
		cachedStatusOK: true,
	})
	st, ok := provider.CachedStatus()
	if !ok || len(st.WorkerRuntime) != 1 || st.WorkerRuntime[0].ThreadCPUNS != 42 {
		t.Fatalf("CachedStatus() after userspace swap = %+v, ok=%v; want the injected status", st, ok)
	}

	d.setDataplane(nil)
	if _, ok := provider.CachedStatus(); ok {
		t.Fatal("CachedStatus() ok=true after teardown, want false")
	}
}

// TestBootstrapExit_ArmFailureWithConcurrentReaders drives the REAL
// bootstrap-exit writer (armBootstrapExitDataplane) with a failing-Start
// fake while the reader shapes churn: -race clean, the cell cleared, and
// the NAT pool monitor NOT started.
//
// r7-F2: the rounds below prove the readers were LIVE on both sides of the
// clear; for this single-shot writer they do not make the store race a
// load, and on a plain-field shadow this test fired 0/5 at GOMAXPROCS=1
// (table in dataplaneCellReaderChurn). The deterministic revert-fires gate
// for THIS store is TestBootstrapExit_RealSamplerOverlap, which parks the
// real forwarding-status sampler and this same writer on one release.
func TestBootstrapExit_ArmFailureWithConcurrentReaders(t *testing.T) {
	d := &Daemon{}
	d.applyBodyForTest = func(_ *config.Config) {}
	d.natPoolAlarmTestTick = time.Millisecond
	d.bootstrapMode.Store(false) // exitBootstrapMode already flipped it in production

	stop := make(chan struct{})
	var churn *dataplaneCellReaderChurn

	// r6-F6: park the writer INSIDE the arm (the fake's Start hook runs
	// immediately before armBootstrapExitDataplane's setDataplane(nil))
	// and hold it there until every reader shape has completed a fresh
	// pass. The write therefore lands with the readers provably live,
	// instead of merely having been live at some earlier point.
	d.setDataplane(&failingStartUserspaceDP{onStart: func() {
		awaitReaderRound(t, churn, "while the arm-failure writer was parked mid-write")
	}})

	churn = churnDataplaneCellReaders(d, stop)
	<-churn.ready // every shape has run at least once

	d.armBootstrapExitDataplane(0)

	// And a round AFTER the store: the readers are proven live on both
	// sides of the cell clear.
	awaitReaderRound(t, churn, "after the arm-failure writer cleared the cell")

	close(stop)
	<-churn.done
	if d.dataplane() != nil {
		t.Fatal("cell must be cleared after the arm failure")
	}
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("monitor must NOT start on a failed arm")
	}
}

// blockingProcReader is the reader-side barrier of the two-sided
// RealSamplerOverlap gate: ReadSelfStat (which Sampler.sample calls BEFORE
// touching the adapter) signals readerEntered and blocks on the shared
// release, so the adapter's dataplane load and the writer's store proceed
// with NO happens-before edge between them.
type blockingProcReader struct {
	fwdstatus.ProcReader
	mu            sync.Mutex
	entries       int
	readerEntered chan struct{}
	release       chan struct{}
	once          sync.Once
}

func (b *blockingProcReader) ReadSelfStat() (fwdstatus.ProcSelfStat, error) {
	b.mu.Lock()
	b.entries++
	b.mu.Unlock()
	b.once.Do(func() {
		close(b.readerEntered)
		<-b.release
	})
	return fwdstatus.ProcSelfStat{UtimeTicks: 10, StimeTicks: 5, StartTimeTicks: 1000}, nil
}

func (b *blockingProcReader) entryCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.entries
}

// TestBootstrapExit_RealSamplerOverlap is the deterministic sampler-vs-
// bootstrap-exit-writer overlap (plan §9, r2 M2 / r3 B1): the gate sits
// BEFORE the dataplane access on BOTH sides with NO channel between the
// conflicting accesses — the fake ProcReader blocks the reader before its
// adapter load; the failing fake's Start blocks the writer before its
// store; both release together. On the plain field the detector fires
// (only the absence of an HB edge is required); on the cell it is clean.
func TestBootstrapExit_RealSamplerOverlap(t *testing.T) {
	d := &Daemon{}
	d.applyBodyForTest = func(_ *config.Config) {}
	d.bootstrapMode.Store(false)
	d.setDataplane(&failingStartUserspaceDP{})

	readerEntered := make(chan struct{})
	writerEntered := make(chan struct{})
	release := make(chan struct{})

	proc := &blockingProcReader{
		ProcReader:    fwdstatus.OSProcReader{},
		readerEntered: readerEntered,
		release:       release,
	}
	ctx, cancel := context.WithCancel(context.Background())
	sampler := fwdstatus.NewSampler(d.forwardingStatusDataplane(), proc)
	// Start MUST run on its own goroutine: its prime sample is synchronous.
	go sampler.Start(ctx)

	// Writer side: the failing fake's Start signals and blocks on the SAME
	// release before returning its error (the setDataplane(nil) store
	// happens after Start returns in armBootstrapExitDataplane).
	fake := &failingStartUserspaceDP{onStart: func() {
		close(writerEntered)
		<-release
	}}
	d.setDataplane(fake)

	writerDone := make(chan struct{})
	go func() { d.armBootstrapExitDataplane(0); close(writerDone) }()

	// Wait for BOTH sides to be parked, then release: the adapter's load
	// and the writer's store proceed with no HB edge.
	<-readerEntered
	<-writerEntered
	close(release)

	<-writerDone
	if d.dataplane() != nil {
		t.Fatal("cell must be cleared after the arm failure")
	}

	// Teardown: the sampler loop exposes no join handle — cancel and then
	// require SUSTAINED quiescence: ReadSelfStat entries must stay stable
	// for >= 2x SampleInterval (bounded by the overall timeout so this
	// cannot hang).
	cancel()
	deadline := time.Now().Add(10 * time.Second)
	last := proc.entryCount()
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		now := proc.entryCount()
		if now != last {
			last = now
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= 2500*time.Millisecond {
			return
		}
	}
	t.Fatal("sampler did not quiesce after cancel")
}

// armedRecorderDP is the recurrence fake: it records Start/Teardown calls
// so the rollback-rearm test can assert the SAME object is retained across
// the rollback and re-Started on the re-arm (Codex PR #6743 r2-8).
type armedRecorderDP struct {
	runtimeOnlyApplyTestDP
	startCalls    int
	teardownCalls int
	failStart     bool
	onStart       func()
}

func (f *armedRecorderDP) Start(context.Context) error {
	f.startCalls++
	// r6-F6: the optional hook parks the writer INSIDE the arm, immediately
	// before armBootstrapExitDataplane's store, so a caller can prove
	// reader passes overlap the write instead of assuming it.
	if f.onStart != nil {
		f.onStart()
	}
	if f.failStart {
		return errors.New("synthetic re-arm failure (#2114 test)")
	}
	return nil
}

func (f *armedRecorderDP) Teardown() error {
	f.teardownCalls++
	return nil
}

// TestDataplaneCell_RollbackRearmRecurrence drives the full recurrence
// with REAL helpers (plan §9): successful arm → monitor starts →
// enterBootstrapMode (monitor discarded, dataplane torn down) → re-exit
// with a failing Start → cell nil, no monitor, -race clean with
// watchdog-shape readers churning throughout. The identity assertions pin
// the retention contract (r2-8): the rollback's Teardown keeps the SAME
// published object in the cell (a clear-on-teardown would strand the
// corrected-commit re-arm), and the re-arm Starts THAT object — a fresh
// replacement would re-arm into a dataplane whose teardown never ran.
//
// r7-F2: those identity/lifecycle assertions are what this test binds. Its
// reader rounds prove LIVENESS, not a race: on a plain-field shadow it
// fired 0/5 at GOMAXPROCS=1 (table in dataplaneCellReaderChurn). The
// deterministic revert-fires gate for the re-arm store is
// TestDataplaneCell_RollbackRearmOverlap.
func TestDataplaneCell_RollbackRearmRecurrence(t *testing.T) {
	// Codex PR #6743 r2-8: run the PRODUCTION teardown path (the default
	// enterBootstrapMode branch → runBootstrapTeardownSteps → the real
	// dataplane Teardown call), not the applyBodyForTest seam that skips
	// it. linkDir is redirected to an empty temp dir so the networkd step
	// removes nothing and never calls networkctl; d.frr is nil so the FRR
	// step is skipped.
	d := &Daemon{}
	prevLinkDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = prevLinkDir })
	d.natPoolAlarmTestTick = time.Millisecond
	d.bootstrapMode.Store(false)
	backend := &armedRecorderDP{}
	d.setDataplane(backend)

	stop := make(chan struct{})
	churn := churnDataplaneCellReaders(d, stop)
	<-churn.ready // every shape has run at least once

	// Successful arm: monitor starts.
	d.armBootstrapExitDataplane(0)
	if d.dataplane() == nil {
		t.Fatal("cell must hold the dataplane after a successful arm")
	}
	if d.natPoolAlarm.Load() == nil {
		t.Fatal("monitor must start on a successful arm")
	}
	if backend.startCalls != 1 || backend.teardownCalls != 0 {
		t.Fatalf("after arm: start=%d teardown=%d, want 1/0", backend.startCalls, backend.teardownCalls)
	}

	// Roll back to bootstrap: the monitor is discarded, the dataplane
	// object is torn down but the cell still holds it (retained for
	// re-arm).
	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("enterBootstrapMode must discard the monitor")
	}
	// r2-8: the rollback's Teardown ran against the SAME object and the
	// cell STILL HOLDS it — clearing on teardown would make the corrected
	// re-arm construct nothing (or a fresh object whose teardown never
	// ran).
	if backend.teardownCalls != 1 {
		t.Fatalf("rollback teardown calls = %d, want 1", backend.teardownCalls)
	}
	if got := d.dataplane(); got != dataplane.RuntimeDataPlane(backend) {
		t.Fatalf("the cell must retain the SAME backend object across the rollback (got %T %p)", got, got)
	}

	// Re-exit with a failing Start on the SAME retained object: the cell
	// clears, no monitor.
	//
	// r6-F6: the re-arm parks inside Start until every reader shape has
	// made a fresh pass, so the clear that follows lands against provably
	// live readers; a second round after it brackets the store on both
	// sides.
	backend.failStart = true
	backend.onStart = func() {
		awaitReaderRound(t, churn, "while the failing re-arm was parked mid-write")
	}
	d.bootstrapMode.Store(false)
	d.armBootstrapExitDataplane(0)
	awaitReaderRound(t, churn, "after the failing re-arm cleared the cell")

	close(stop)
	<-churn.done
	if backend.startCalls != 2 {
		t.Fatalf("re-arm Start calls = %d, want 2 (the retained object is re-Started, not replaced)", backend.startCalls)
	}
	if d.dataplane() != nil {
		t.Fatal("cell must be cleared after the re-arm failure")
	}
	if d.natPoolAlarm.Load() != nil {
		t.Fatal("no monitor may survive the failed re-arm")
	}
}

// TestDataplaneCell_RollbackRearmOverlap is the DETERMINISTIC revert-fires
// gate for the rollback + re-arm store (Codex PR #6743 r7-F2), the
// counterpart of TestBootstrapExit_RealSamplerOverlap for the plain
// arm-failure store.
//
// TestDataplaneCell_RollbackRearmRecurrence brackets that store with reader
// ROUNDS, which prove the readers were live on both sides but leave no
// conflicting pair unordered for a single-shot writer — measured 0/5 on a
// plain-field shadow at GOMAXPROCS=1 (see dataplaneCellReaderChurn). This
// test supplies the missing half and asserts nothing about identity or
// monitor lifecycle, which the recurrence test already covers.
//
// The gate sits BEFORE the dataplane access on BOTH sides with NO channel
// between the conflicting accesses: the reader parks immediately before its
// dataplane() load, the retained backend's re-arm Start parks immediately
// before armBootstrapExitDataplane's setDataplane(nil), and ONE close
// releases both. Only the absence of a happens-before edge is required, so
// on the plain-field revert the detector fires at any GOMAXPROCS; on the
// cell it is clean.
func TestDataplaneCell_RollbackRearmOverlap(t *testing.T) {
	// Same production teardown path as the recurrence test: linkDir points
	// at an empty temp dir so the networkd step removes nothing, and d.frr
	// is nil so the FRR step is skipped. No churn and no NAT pool monitor
	// here — the gated pair IS the test, and extra readers only add shadow
	// traffic on the field under observation.
	d := &Daemon{}
	prevLinkDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = prevLinkDir })
	d.bootstrapMode.Store(false)

	backend := &armedRecorderDP{}
	d.setDataplane(backend)

	// Roll back to bootstrap: the object is torn down but RETAINED in the
	// cell, which is the state a corrected commit re-arms.
	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}
	if backend.teardownCalls != 1 {
		t.Fatalf("rollback teardown calls = %d, want 1", backend.teardownCalls)
	}
	if got := d.dataplane(); got != dataplane.RuntimeDataPlane(backend) {
		t.Fatalf("the cell must retain the backend across the rollback (got %T)", got)
	}

	readerParked := make(chan struct{})
	writerParked := make(chan struct{})
	release := make(chan struct{})

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		// The watchdog reader shape (one load per tick, then the HA domain),
		// parked immediately before the load.
		close(readerParked)
		<-release
		if rt := d.dataplane(); rt != nil {
			_ = rt.HA().SetRGActive(context.Background(), 0, true)
		}
	}()

	backend.failStart = true
	backend.onStart = func() {
		close(writerParked)
		<-release
	}
	d.bootstrapMode.Store(false)

	go func() {
		<-readerParked
		<-writerParked
		close(release)
	}()

	d.armBootstrapExitDataplane(0)
	<-readerDone

	if backend.startCalls != 1 {
		t.Fatalf("re-arm Start calls = %d, want 1 (the RETAINED object is re-Started)", backend.startCalls)
	}
	if d.dataplane() != nil {
		t.Fatal("cell must be cleared after the re-arm failure")
	}
}

// TestDataplaneCell_ClusterStartPublication is the RACE-1 shape: a
// watcher-chain reader loop (the daemon_ha.go handler pattern — one load
// per event, SetRGActive through the HA domain) racing the boot
// setDataplane(dp) publication. Every load observes nil or the full slot;
// never a torn interface (the detector fires on a plain-field revert).
//
// Codex PR #6743 r4-F3: the two 2 ms sleeps that used to bracket the
// publication are gone. They were the ONLY thing making the reader
// overlap the writer, and a loaded CI box could schedule the whole
// writer between them. Both edges are now rendezvous channels: sawNil
// proves the reader ran against the EMPTY cell before publication, and
// sawPublished proves it ran against the FULL slot after — so the
// overlap is a property of the test, not of the scheduler.
func TestDataplaneCell_ClusterStartPublication(t *testing.T) {
	d := &Daemon{}
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	sawNil := make(chan struct{})
	sawPublished := make(chan struct{})
	go func() {
		defer close(readerDone)
		var nilOnce, publishedOnce sync.Once
		for {
			select {
			case <-stop:
				return
			default:
				rt := d.dataplane()
				if rt == nil {
					nilOnce.Do(func() { close(sawNil) })
					continue
				}
				// The watcher handler chain shape: HA() + SetRGActive.
				_ = rt.HA().SetRGActive(context.Background(), 0, true)
				publishedOnce.Do(func() { close(sawPublished) })
			}
		}
	}()

	<-sawNil // the reader is live and spinning on the empty cell
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	<-sawPublished // the reader dispatched through the published slot
	close(stop)
	<-readerDone
	if d.dataplane() == nil {
		t.Fatal("publication lost")
	}
}

// TestDataplaneCell_ConfirmTimerStoreVsApplyReader is the RACE-3 pure-cell
// leg (plan §9, r68 Codex m1 — no G/H/H2 dependency): a two-sided gate
// with the publication gated immediately before the Store and an
// applySem-holding reader gated immediately before its dataplane() load,
// sharing one release — no channel between the pair.
func TestDataplaneCell_ConfirmTimerStoreVsApplyReader(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	// The recovered confirm-timer executor's rollback apply holds applySem
	// while reading the dataplane; take it here so the reader goroutine
	// below runs inside the same critical-section discipline.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("applySem acquire: %v", err)
	}

	writerReady := make(chan struct{})
	readerReady := make(chan struct{})
	release := make(chan struct{})

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		fake := &runtimeOnlyApplyTestDP{}
		close(writerReady)
		<-release
		d.setDataplane(fake)
	}()

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		// The recovered confirm-timer executor's rollback apply holds
		// applySem while reading the dataplane (bootstrap.go teardown).
		close(readerReady)
		<-release
		rt := d.dataplane()
		if rt != nil {
			_ = rt.Teardown()
		}
	}()

	<-writerReady
	<-readerReady
	close(release)
	<-writerDone
	<-readerDone
	d.applySem.Release(1)

	if d.dataplane() == nil {
		t.Fatal("publication lost")
	}
}
