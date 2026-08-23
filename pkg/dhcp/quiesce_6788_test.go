package dhcp

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// shortDebounce shrinks the recompile debounce so the post-quiesce timer race
// is exercised in milliseconds rather than across a 2s wall clock.
func shortDebounce(t *testing.T, d time.Duration) {
	t.Helper()
	saved := recompileDebounce
	recompileDebounce = d
	t.Cleanup(func() { recompileDebounce = saved })
}

// countingManager returns a Manager whose address-change callback increments a
// counter, plus the counter.
func countingManager(t *testing.T) (*Manager, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	m := &Manager{
		clients: make(map[clientKey]*dhcpClient),
		leases:  make(map[clientKey]*Lease),
	}
	m.onAddressChange = func() { n.Add(1) }
	return m, &n
}

// TestQuiesceStopsArmedRecompileTimer6788 is the deterministic post-drain timer
// test. An address change arms a debounce timer whose callback re-enters a FULL
// config apply; at 2s in production that is long enough to outlive the
// shutdown apply drain and land in a half-torn-down daemon. After Quiesce the
// armed timer must not dispatch.
//
// FAIL-ON-REVERT: dropping the timer Stop (or the post-latch re-test inside the
// timer func) lets the callback fire and the counter reach 1.
func TestQuiesceStopsArmedRecompileTimer6788(t *testing.T) {
	shortDebounce(t, 40*time.Millisecond)
	m, fired := countingManager(t)

	m.scheduleRecompile() // arm it, as a lease change does
	m.Quiesce()

	// Wait well past the debounce: if the timer survived, it has fired by now.
	time.Sleep(200 * time.Millisecond)
	if got := fired.Load(); got != 0 {
		t.Fatalf("the address-change callback fired %d time(s) after Quiesce; an armed debounce "+
			"timer that survives shutdown re-enters a full config apply AFTER the apply drain "+
			"(#6788)", got)
	}
	if !m.Quiesced() {
		t.Error("Quiesce must latch")
	}
}

// TestQuiesceLatchRefusesLaterScheduling6788 covers the race the Stop alone
// cannot: a lease event arriving CONCURRENTLY with shutdown re-arms the timer
// after Quiesce stopped it. The latch must make scheduleRecompile arm nothing.
//
// FAIL-ON-REVERT: removing the `if m.quiesced { return }` guard from
// scheduleRecompile lets the re-arm succeed and the callback fires.
func TestQuiesceLatchRefusesLaterScheduling6788(t *testing.T) {
	shortDebounce(t, 40*time.Millisecond)
	m, fired := countingManager(t)

	m.Quiesce()
	m.scheduleRecompile() // a lease event racing the shutdown

	time.Sleep(200 * time.Millisecond)
	if got := fired.Load(); got != 0 {
		t.Fatalf("scheduleRecompile armed a timer after Quiesce (callback fired %d time(s)): the "+
			"latch must be one-way, or a lease event racing shutdown re-opens the window (#6788)", got)
	}
	m.mu.Lock()
	armed := m.recompileTimer != nil
	m.mu.Unlock()
	if armed {
		t.Error("no timer should be armed after a quiesced scheduleRecompile")
	}
}

// TestQuiescePreservesLeasesAndClients6788 is the control that fails the
// OBVIOUS fix. The reflex repair for "a DHCP timer fires after shutdown" is to
// call StopAll from runShutdownSequence — and StopAll cancels every client,
// which runs finishClient -> removeAddress. On a box whose management interface
// is DHCP (fxp0) that strips the management address during shutdown and leaves
// it stripped across a graceful restart, which is the precise contract the
// client-context comment in startClient preserves: clients are decoupled from
// the daemon lifecycle so "during graceful restart (SIGTERM), the process exits
// without calling StopAll(), so addresses stay on interfaces for the next
// daemon to reuse".
//
// Quiesce must therefore leave leases, the client registry, and the callback
// registration itself untouched — it shuts off notification, not DHCP.
//
// FAIL-ON-REVERT: implementing Quiesce as StopAll (or having it cancel clients
// / drop leases) empties the registry and reds this.
func TestQuiescePreservesLeasesAndClients6788(t *testing.T) {
	m, _ := countingManager(t)

	key := clientKey{iface: "fxp0", family: AFInet}
	m.clients[key] = &dhcpClient{done: make(chan struct{})}
	m.leases[key] = &Lease{Address: netip.MustParsePrefix("10.0.0.5/24")}

	m.Quiesce()

	if len(m.clients) != 1 {
		t.Errorf("Quiesce must NOT stop DHCP clients: registry has %d client(s), want 1. "+
			"Cancelling a client runs removeAddress, which strips the address from a "+
			"DHCP-managed management interface (#6788)", len(m.clients))
	}
	if got, ok := m.leases[key]; !ok || !got.Address.IsValid() {
		t.Errorf("Quiesce must PRESERVE leases so the next daemon can reuse the address; lease=%v ok=%v",
			got, ok)
	}
	if m.onAddressChange == nil {
		t.Error("Quiesce must not tear down the callback registration itself — the latch is what " +
			"suppresses dispatch, and clearing the hook would make a restart-in-place silently deaf")
	}
}

// TestQuiesceJoinsInFlightCallback6788 pins the JOIN. A timer that has already
// elapsed cannot be un-fired by Stop, so a callback can be mid-flight when
// Quiesce is called. Quiesce must not return until it finishes, otherwise the
// caller orders its teardown after a callback that is still running — which is
// the same late-apply hazard with a narrower window.
//
// FAIL-ON-REVERT: dropping the recompileWG.Wait() lets Quiesce return while the
// callback is still inside its body, and the "finished" flag is still false.
func TestQuiesceJoinsInFlightCallback6788(t *testing.T) {
	shortDebounce(t, 10*time.Millisecond)

	entered := make(chan struct{})
	release := make(chan struct{})
	var finished atomic.Bool

	m := &Manager{
		clients: make(map[clientKey]*dhcpClient),
		leases:  make(map[clientKey]*Lease),
	}
	m.onAddressChange = func() {
		close(entered)
		<-release
		finished.Store(true)
	}

	m.scheduleRecompile()
	<-entered // the callback is now running

	done := make(chan struct{})
	go func() { m.Quiesce(); close(done) }()

	// Quiesce must still be waiting on the in-flight callback.
	select {
	case <-done:
		t.Fatal("Quiesce returned while the address-change callback was still running; the caller " +
			"would then order teardown after work that has not finished (#6788)")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Quiesce did not return after the in-flight callback completed")
	}
	if !finished.Load() {
		t.Error("Quiesce returned before the in-flight callback finished")
	}
}
