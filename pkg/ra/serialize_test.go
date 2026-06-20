package ra

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/psaab/xpf/pkg/config"
)

// writeRec is one recorded RA write: its router lifetime and a monotonic
// sequence number assigned in write order (NOT wall-clock — deterministic).
type writeRec struct {
	lifetime time.Duration
	seq      int
}

// fakeConn is an ndpConn test double. It records every WriteTo (lifetime +
// monotonic seq), serves injected Router Solicitations from a queue on
// ReadFrom, and counts how many live conns exist (so the <=1-live-conn-per-
// interface invariant can be asserted). All methods are safe for concurrent
// use, matching the real conn's documented WriteTo concurrency.
type fakeConn struct {
	mu     sync.Mutex
	writes []writeRec
	seq    int
	closed bool

	// rsQueue holds injected RS source addresses. ReadFrom pops one per call;
	// when empty it blocks until rsSignal fires or the conn is closed, then
	// returns a timeout error so the receiver polls stopCh.
	rsQueue  []netip.Addr
	rsSignal chan struct{}

	// liveCounter, if non-nil, is incremented on construction (by the
	// listenFn) and decremented on Close — the invariant probe.
	liveCounter *int32
	liveMu      *sync.Mutex

	// beforeWrite, if non-nil, is invoked at the top of every WriteTo so a
	// test can block a specific send to force an interleave. Stored in an
	// atomic.Pointer and read without holding f.mu so the hook (which may
	// block) does not deadlock against the recording lock, and so concurrent
	// set-by-test / read-by-owner is race-free.
	beforeWrite atomic.Pointer[func(lifetime time.Duration)]
}

func newFakeConn() *fakeConn {
	return &fakeConn{rsSignal: make(chan struct{}, 1)}
}

// setBeforeWrite installs (or clears, with nil) the WriteTo hook race-free.
func (f *fakeConn) setBeforeWrite(fn func(lifetime time.Duration)) {
	if fn == nil {
		f.beforeWrite.Store(nil)
		return
	}
	f.beforeWrite.Store(&fn)
}

func (f *fakeConn) WriteTo(m ndp.Message, _ *ipv6.ControlMessage, _ netip.Addr) error {
	ra, ok := m.(*ndp.RouterAdvertisement)
	if !ok {
		return nil
	}
	if hook := f.beforeWrite.Load(); hook != nil {
		(*hook)(ra.RouterLifetime)
	}
	f.mu.Lock()
	f.seq++
	f.writes = append(f.writes, writeRec{lifetime: ra.RouterLifetime, seq: f.seq})
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil, nil, netip.Addr{}, errClosed{}
		}
		if len(f.rsQueue) > 0 {
			src := f.rsQueue[0]
			f.rsQueue = f.rsQueue[1:]
			f.mu.Unlock()
			return &ndp.RouterSolicitation{}, nil, src, nil
		}
		f.mu.Unlock()
		// No RS queued: wait for a signal or a short tick, then return a
		// timeout so rsReceiver polls stopCh (matching the real read deadline).
		select {
		case <-f.rsSignal:
			continue
		case <-time.After(20 * time.Millisecond):
			return nil, nil, netip.Addr{}, errTimeout{}
		}
	}
}

func (f *fakeConn) injectRS(src netip.Addr) {
	f.mu.Lock()
	f.rsQueue = append(f.rsQueue, src)
	f.mu.Unlock()
	select {
	case f.rsSignal <- struct{}{}:
	default:
	}
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	already := f.closed
	f.closed = true
	f.mu.Unlock()
	// Wake any blocked ReadFrom.
	select {
	case f.rsSignal <- struct{}{}:
	default:
	}
	if !already && f.liveCounter != nil {
		f.liveMu.Lock()
		*f.liveCounter--
		f.liveMu.Unlock()
	}
	return nil
}

func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeConn) JoinGroup(netip.Addr) error       { return nil }
func (f *fakeConn) SetICMPFilter(*ipv6.ICMPFilter) error {
	return nil
}

func (f *fakeConn) snapshot() []writeRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]writeRec, len(f.writes))
	copy(out, f.writes)
	return out
}

// errTimeout / errClosed implement net.Error-ish Timeout() for isTimeout.
type errTimeout struct{}

func (errTimeout) Error() string { return "i/o timeout" }
func (errTimeout) Timeout() bool { return true }

type errClosed struct{}

func (errClosed) Error() string { return "use of closed connection" }
func (errClosed) Timeout() bool { return false }

// testCfg returns a minimal RA config for an interface.
func testCfg(iface string) *config.RAInterfaceConfig {
	return &config.RAInterfaceConfig{
		Interface:      iface,
		DefaultLifetime: 1800,
		MaxAdvInterval:  600,
		MinAdvInterval:  200,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	}
}

// fakeListen is the test harness wiring listenFn + ensureLinkLocalFn to fakes.
type fakeListen struct {
	mu       sync.Mutex
	conns    map[string]*fakeConn
	prehooks map[string]func(time.Duration) // installed at conn-creation time
	live     int32
	liveMu   sync.Mutex
}

// installFakeListen wires listenFn + ensureLinkLocalFn to fakes for the
// duration of the test and restores them on cleanup. getConn returns the
// fakeConn most recently opened for an interface name; liveCount returns the
// number of live (open) conns.
func installFakeListen(t *testing.T) (getConn func(string) *fakeConn, liveCount func() int32) {
	t.Helper()
	fl := newFakeListen(t)
	return fl.getConn, fl.liveCount
}

func newFakeListen(t *testing.T) *fakeListen {
	t.Helper()
	origListen := listenFn
	origEnsure := ensureLinkLocalFn

	fl := &fakeListen{
		conns:    map[string]*fakeConn{},
		prehooks: map[string]func(time.Duration){},
	}

	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		fc := newFakeConn()
		fc.liveCounter = &fl.live
		fc.liveMu = &fl.liveMu
		fl.liveMu.Lock()
		fl.live++
		fl.liveMu.Unlock()
		fl.mu.Lock()
		if h := fl.prehooks[iface.Name]; h != nil {
			fc.setBeforeWrite(h) // attach BEFORE the owner can write
		}
		fl.conns[iface.Name] = fc
		fl.mu.Unlock()
		return fc, netip.MustParseAddr("fe80::1"), nil
	}

	t.Cleanup(func() {
		listenFn = origListen
		ensureLinkLocalFn = origEnsure
	})
	return fl
}

// preHook registers a WriteTo hook that is attached to the next conn opened for
// name, at conn-creation time, so it is in place before the owner's first
// write (avoids a race between start() and a post-start setBeforeWrite).
func (fl *fakeListen) preHook(name string, fn func(time.Duration)) {
	fl.mu.Lock()
	fl.prehooks[name] = fn
	fl.mu.Unlock()
}

func (fl *fakeListen) getConn(name string) *fakeConn {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return fl.conns[name]
}

func (fl *fakeListen) liveCount() int32 {
	fl.liveMu.Lock()
	defer fl.liveMu.Unlock()
	return fl.live
}

// fakeIfaceByName must be set because startLocked calls net.InterfaceByName.
// We can't stub that, so tests use a loopback-style interface that exists, or
// rely on the manager path that does NOT resolve a real interface. To keep
// these unit tests hermetic, we drive sender.start() directly with a synthetic
// *net.Interface (bypassing net.InterfaceByName) where possible, and use the
// Manager only in tests that go through real interface resolution via a name
// guaranteed to exist ("lo").

// startFakeSender builds a sender with a synthetic interface and the fake conn
// machinery, starts it, and returns it plus its fakeConn.
func startFakeSender(t *testing.T, getConn func(string) *fakeConn, name string) (*sender, *fakeConn) {
	t.Helper()
	iface := &net.Interface{Name: name, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg(name), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Give the owner a moment to open the conn via listenFn.
	fc := waitConn(t, getConn, name)
	return s, fc
}

func waitConn(t *testing.T, getConn func(string) *fakeConn, name string) *fakeConn {
	t.Helper()
	for i := 0; i < 200; i++ {
		if fc := getConn(name); fc != nil {
			return fc
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("conn for %s never opened", name)
	return nil
}

// waitWrites blocks until fc has recorded at least n writes (or fails).
func waitWrites(t *testing.T, fc *fakeConn, n int) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if len(fc.snapshot()) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d writes recorded, want >=%d", len(fc.snapshot()), n)
}

// assertGoodbyeIsLast asserts the #2033 invariant: no lifetime>0 write has a
// seq greater than the FIRST lifetime-0 (goodbye) write. (Per Codex r3 MINOR
// #5 — asserting against the FIRST goodbye, not merely "last write is a
// goodbye," which a normal RA interleaved between goodbye packets would pass.)
func assertGoodbyeIsLast(t *testing.T, writes []writeRec) {
	t.Helper()
	firstGoodbye := -1
	for _, w := range writes {
		if w.lifetime == 0 {
			firstGoodbye = w.seq
			break
		}
	}
	if firstGoodbye < 0 {
		t.Fatalf("no goodbye (lifetime=0) RA was emitted; writes=%+v", writes)
	}
	for _, w := range writes {
		if w.lifetime > 0 && w.seq > firstGoodbye {
			t.Fatalf("normal RA (lifetime=%v, seq=%d) emitted AFTER the first goodbye (seq=%d); writes=%+v",
				w.lifetime, w.seq, firstGoodbye, writes)
		}
	}
}

// T1 — headline ordering proof under a FORCED bad interleave. An RS is queued
// and the owner enters the RS random-sleep branch; the test holds the in-flight
// normal RA WriteTo until AFTER the withdraw has been signalled, then releases
// it. The invariant (no lifetime>0 after the first goodbye) must hold: the
// in-flight normal RA precedes the goodbye because the goodbye is emitted by the
// owner on exit (finishShutdown), structurally after the loop.
func TestT1_GoodbyeIsLastUnderForcedRSInterleave(t *testing.T) {
	getConn, _ := installFakeListen(t)

	iface := &net.Interface{Name: "t1iface", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	cfg := testCfg("t1iface")
	// Fresh sender: getLastRA() is zero so the RS rate-limit gate passes and
	// the RS triggers a normal RA reply.
	s := newSender(cfg, iface)

	// Gate state: after the startup burst, the NEXT normal RA (the RS reply) is
	// blocked until `released` so we can interleave the withdraw with it.
	released := make(chan struct{})
	blocked := make(chan struct{})
	armNormalGate := make(chan struct{}) // closed once we want to start gating
	var gateOnce sync.Once

	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, getConn, "t1iface")
	// Let the startup burst complete so the next normal RA is the RS reply.
	waitWrites(t, fc, startupBurstCount)

	fc.setBeforeWrite(func(lifetime time.Duration) {
		if lifetime <= 0 {
			return // never block the goodbye
		}
		select {
		case <-armNormalGate:
			gateOnce.Do(func() {
				close(blocked)
				<-released
			})
		default:
			// burst writes (gate not armed yet) pass through
		}
	})

	// Push lastRA into the past so the RS rate-limit (minRAMulticastDelay)
	// passes and the RS produces a reply (the startup burst just set lastRA to
	// now, which would otherwise suppress the reply).
	s.setLastRA(time.Now().Add(-2 * minRAMulticastDelay))

	// Arm the gate, then inject an RS. The owner rate-checks (passes),
	// random-sleeps, then sendRA -> WriteTo hits the gate and blocks.
	close(armNormalGate)
	fc.injectRS(netip.MustParseAddr("fe80::2"))

	// Wait until the RS-reply normal RA is genuinely blocked in WriteTo.
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("RS-reply normal RA never reached the write gate")
	}

	// The in-flight normal RA is blocked. Signal graceful withdraw NOW.
	s.signalStop(modeGraceful)

	// Release the blocked normal RA, then join. The goodbye is emitted by the
	// owner on exit, structurally after this normal RA.
	close(released)
	<-s.stopped

	assertGoodbyeIsLast(t, fc.snapshot())
}

// T1b — companion micro-test: force a periodic-timer-style normal RA concurrent
// with the withdraw and assert the same seq-order property. We drive it by
// blocking a normal write and signalling stop while it is in flight.
func TestT1b_GoodbyeIsLastWithInFlightNormalRA(t *testing.T) {
	fl := newFakeListen(t)
	iface := &net.Interface{Name: "t1biface", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("t1biface"), iface)

	released := make(chan struct{})
	blocked := make(chan struct{})
	var once sync.Once

	// Pre-register the gate so it is attached before the owner's first burst
	// write (no race between start() and a post-start hook install).
	fl.preHook("t1biface", func(lifetime time.Duration) {
		if lifetime > 0 {
			once.Do(func() {
				close(blocked)
				<-released
			})
		}
	})

	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, fl.getConn, "t1biface")

	// The startup burst's first normal RA hits the gate.
	<-blocked
	// Now a normal RA is in flight (blocked). Signal graceful withdraw.
	s.signalStop(modeGraceful)
	// Release it; owner finishes burst (short-circuited by draining), then
	// finishShutdown emits the goodbye last.
	close(released)
	<-s.stopped

	assertGoodbyeIsLast(t, fc.snapshot())
}

// TestNegativeArm proves the test is NOT tautological: a "buggy" sender that
// emits a normal RA AFTER the goodbye must FAIL assertGoodbyeIsLast. We
// construct the bad write sequence directly (simulating the pre-#2033 behavior
// where a periodic RA followed the caller-emitted goodbye).
func TestNegativeArm_NormalRAAfterGoodbyeFails(t *testing.T) {
	bad := []writeRec{
		{lifetime: 1800 * time.Second, seq: 1}, // normal
		{lifetime: 0, seq: 2},                  // goodbye
		{lifetime: 1800 * time.Second, seq: 3}, // BUG: normal after goodbye
	}
	// Run assertGoodbyeIsLast in a sub-test that is EXPECTED to fail; capture
	// via a fake testing.T.
	ft := &fakeT{}
	assertGoodbyeIsLastOn(ft, bad)
	if !ft.failed {
		t.Fatal("negative arm did not fail: a normal RA after the goodbye must FAIL the invariant")
	}

	// And the good sequence must pass.
	good := []writeRec{
		{lifetime: 1800 * time.Second, seq: 1},
		{lifetime: 0, seq: 2},
		{lifetime: 0, seq: 3},
	}
	ft2 := &fakeT{}
	assertGoodbyeIsLastOn(ft2, good)
	if ft2.failed {
		t.Fatal("good sequence wrongly failed the invariant")
	}
}

// fakeT records whether Fatalf was called so the negative arm can assert the
// invariant predicate FAILS on a bad sequence without aborting the real test.
type fakeT struct{ failed bool }

func (f *fakeT) Helper()                       {}
func (f *fakeT) Fatalf(string, ...interface{}) { f.failed = true; panic(sentinelFatal{}) }

type sentinelFatal struct{}

// assertGoodbyeIsLastOn is assertGoodbyeIsLast against a minimal fatal-er so it
// can be exercised by the negative arm. It recovers the sentinel panic.
func assertGoodbyeIsLastOn(ft *fakeT, writes []writeRec) {
	defer func() { _ = recover() }()
	firstGoodbye := -1
	for _, w := range writes {
		if w.lifetime == 0 {
			firstGoodbye = w.seq
			break
		}
	}
	if firstGoodbye < 0 {
		ft.Fatalf("no goodbye")
		return
	}
	for _, w := range writes {
		if w.lifetime > 0 && w.seq > firstGoodbye {
			ft.Fatalf("normal after goodbye")
			return
		}
	}
}

// TestLiveConnInvariant proves at most one live NDP conn exists per interface
// across start/withdraw/restart cycles. Uses the Manager so the draining
// tombstone is exercised end-to-end. The interface name must resolve via
// net.InterfaceByName, so we use "lo".
func TestLiveConnInvariant(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	_, liveCount := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}

	for cycle := 0; cycle < 10; cycle++ {
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("cycle %d Apply: %v", cycle, err)
		}
		// At most one live conn at any time.
		if lc := liveCount(); lc > 1 {
			t.Fatalf("cycle %d: %d live conns after Apply, want <=1", cycle, lc)
		}
		if err := m.Withdraw(); err != nil {
			t.Fatalf("cycle %d Withdraw: %v", cycle, err)
		}
		if lc := liveCount(); lc != 0 {
			t.Fatalf("cycle %d: %d live conns after Withdraw, want 0", cycle, lc)
		}
	}
}

// TestLiveConnInvariant_ConcurrentApplyWithdraw hammers Apply/Withdraw/
// WithdrawOnce/ResendBurst concurrently and asserts the live-conn count never
// exceeds 1 for the single interface. A design that allowed two live conns
// (e.g. starting a new sender while the old one is still draining) would trip
// the peak check.
func TestLiveConnInvariant_ConcurrentApplyWithdraw(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	_, liveCount := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}

	stop := make(chan struct{})
	var peak int32
	var peakMu sync.Mutex
	recordPeak := func() {
		lc := liveCount()
		peakMu.Lock()
		if lc > peak {
			peak = lc
		}
		peakMu.Unlock()
	}

	var wg sync.WaitGroup
	worker := func(fn func()) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			fn()
			recordPeak()
		}
	}
	wg.Add(4)
	go worker(func() { _ = m.Apply(cfg) })
	go worker(func() { _ = m.Withdraw() })
	go worker(func() { m.WithdrawOnce(cfg) })
	go worker(func() { m.ResendBurst() })

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Drain to a known state.
	_ = m.Clear()

	peakMu.Lock()
	p := peak
	peakMu.Unlock()
	if p > 1 {
		t.Fatalf("peak live conns = %d, want <=1 (two live conns per interface)", p)
	}
	if lc := liveCount(); lc != 0 {
		t.Fatalf("leaked %d live conns after Clear", lc)
	}
}

// T3 — WithdrawOnce emits ONLY a goodbye (no startup burst) and never toggles
// the link. ensureLinkLocalFn is stubbed to record calls; we assert it is NOT
// invoked (the standalone path skips ensureLinkLocal entirely).
func TestT3_WithdrawOnceGoodbyeOnlyNoBurstNoLinkToggle(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	// Override ensureLinkLocalFn to record invocation (installFakeListen set it
	// to a no-op; wrap that to detect calls).
	var linkToggled bool
	prev := ensureLinkLocalFn
	ensureLinkLocalFn = func(i *net.Interface) error { linkToggled = true; return prev(i) }
	t.Cleanup(func() { ensureLinkLocalFn = prev })

	m := New()
	m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})

	fc := getConn("lo")
	if fc == nil {
		t.Fatal("no conn opened for WithdrawOnce")
	}
	writes := fc.snapshot()
	if len(writes) != goodbyeCount {
		t.Fatalf("WithdrawOnce wrote %d RAs, want exactly %d goodbyes", len(writes), goodbyeCount)
	}
	for _, w := range writes {
		if w.lifetime != 0 {
			t.Fatalf("WithdrawOnce emitted a lifetime>0 RA (%v) — startup burst leaked", w.lifetime)
		}
	}
	if linkToggled {
		t.Fatal("WithdrawOnce invoked ensureLinkLocal (link toggle) — violates I12 no-link-toggle")
	}
}

// T4a — WithdrawOnce skips a running sender (does not clobber a live primary).
func TestT4a_WithdrawOnceSkipsRunningSender(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1) // at least the first startup RA

	before := fc.snapshot()
	m.WithdrawOnce(cfg) // should be a no-op (sender running)
	after := fc.snapshot()

	for _, w := range after[len(before):] {
		if w.lifetime == 0 {
			t.Fatal("WithdrawOnce emitted a goodbye on a live primary's conn")
		}
	}
	_ = m.Clear()
}

// T5 — Apply with an identical config keeps the sender (no stop/start, no
// goodbye, same conn).
func TestT5_ApplyConfigEqualKeepsSender(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, liveCount := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply1: %v", err)
	}
	fc1 := waitConn(t, getConn, "lo")

	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply2: %v", err)
	}
	fc2 := getConn("lo")
	if fc1 != fc2 {
		t.Fatal("config-equal Apply restarted the sender (new conn)")
	}
	if lc := liveCount(); lc != 1 {
		t.Fatalf("live conns = %d after config-equal Apply, want 1", lc)
	}
	for _, w := range fc1.snapshot() {
		if w.lifetime == 0 {
			t.Fatal("config-equal Apply emitted a goodbye")
		}
	}
	_ = m.Clear()
}

// T6 — Clear / Apply-remove emit NO goodbye (modeHard).
func TestT6_ClearEmitsNoGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1)
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for _, w := range fc.snapshot() {
		if w.lifetime == 0 {
			t.Fatal("Clear emitted a goodbye (lifetime=0); hard stop must not")
		}
	}
}

// T7 — idempotent / graceful-upgrades-hard. Both orderings must STILL produce
// a goodbye (graceful wins; never downgrade), and a double signalStop must not
// panic. Both signals are issued while the owner is PARKED at a write gate so
// the two Stores complete (happen-before) the owner reading mode in
// finishShutdown — testing the achievable, deterministic guarantee rather than
// the documented sub-µs residual (which only exists when the owner has already
// read modeHard before the upgrade Store; the manager serializes real callers
// via m.mu so that residual is not on the production demotion path).
func TestT7_GracefulUpgradesHard(t *testing.T) {
	run := func(name string, first, second shutdownMode) {
		fl := newFakeListen(t)
		release := make(chan struct{})
		parked := make(chan struct{})
		var once sync.Once
		// Park the owner at its FIRST write so both signalStops land before the
		// owner ever reads mode.
		fl.preHook(name, func(time.Duration) {
			once.Do(func() { close(parked); <-release })
		})

		iface := &net.Interface{Name: name, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
		s := newSender(testCfg(name), iface)
		if err := s.start(); err != nil {
			t.Fatalf("[%s] start: %v", name, err)
		}
		fc := waitConn(t, fl.getConn, name)

		<-parked // owner is blocked in its first WriteTo
		s.signalStop(first)
		s.signalStop(second) // double signal must not panic (sync.Once)
		close(release)       // owner now proceeds; reads the arbitrated mode
		<-s.stopped

		assertGoodbyeIsLast(t, fc.snapshot())
	}

	run("t7a", modeHard, modeGraceful)     // hard then graceful -> graceful wins
	run("t7b", modeGraceful, modeHard)     // graceful then hard -> no downgrade
}

// T9 — startup burst preserved: a fresh start records exactly
// startupBurstCount normal RAs (before any periodic fire).
func TestT9_StartupBurstPreserved(t *testing.T) {
	getConn, _ := installFakeListen(t)
	iface := &net.Interface{Name: "t9", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("t9"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, getConn, "t9")
	waitWrites(t, fc, startupBurstCount)
	writes := fc.snapshot()
	// The first startupBurstCount writes must all be normal RAs.
	for i := 0; i < startupBurstCount; i++ {
		if writes[i].lifetime == 0 {
			t.Fatalf("burst write %d was a goodbye, want normal RA", i)
		}
	}
	s.stop()
}

// TestStatusReportsDraining verifies Status surfaces a draining interface with
// State "draining" (distinct from "active"). We hold a sender in finishShutdown
// by blocking its goodbye write, then snapshot Status while it drains.
func TestStatusReportsDraining(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1)

	// Block the goodbye so the sender lingers in the draining tombstone.
	gate := make(chan struct{})
	fc.setBeforeWrite(func(lifetime time.Duration) {
		if lifetime == 0 {
			<-gate
		}
	})

	done := make(chan struct{})
	go func() { _ = m.Withdraw(); close(done) }()

	// Poll Status until the draining entry appears.
	var sawDraining bool
	for i := 0; i < 200; i++ {
		for _, info := range m.Status() {
			if info.Interface == "lo" && info.State == "draining" {
				sawDraining = true
			}
		}
		if sawDraining {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(gate)
	<-done

	if !sawDraining {
		t.Fatal("Status never reported the withdrawing interface as draining")
	}
	// After drain, no draining entry remains.
	for _, info := range m.Status() {
		if info.State == "draining" {
			t.Fatalf("draining entry lingered after Withdraw completed: %+v", info)
		}
	}
}
