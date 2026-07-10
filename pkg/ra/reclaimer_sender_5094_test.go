package ra

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #5094: when a draining sender's owner wedges past claimWaitTimeout,
// releaseDrain hands the tombstone to the detached reclaimer. The pre-#5094
// reclaimer merely delete()d the tombstone once the wedged owner finally
// exited, DROPPING the generation's owed action — the changed-config
// replacement or the terminal goodbye. The interface could then stay senderless
// (or lose its goodbye) until an unrelated later Apply happened to re-drive it.
//
// The fix: the reclaimer runs the SAME ordered post-close decision releaseDrain
// would have run inline had the join not timed out — start the still-current
// replacement and/or emit the owed goodbye, re-evaluated against fresh state
// under the lock — before removing the tombstone. These tests pin both halves,
// each RED against the pre-#5094 delete-only reclaimer.

// statusJoinTimedOut reports whether Manager.Status surfaces name as a draining
// interface whose owner wedged past the join timeout (#5094 status surface).
func statusJoinTimedOut(m *Manager, name string) bool {
	for _, info := range m.Status() {
		if info.Interface == name && info.State == "draining" && info.JoinTimedOut {
			return true
		}
	}
	return false
}

// waitDrainCleared blocks until name's draining tombstone is gone (the
// reclaimer's final act) or a generous deadline elapses.
func waitDrainCleared(t *testing.T, m *Manager, name string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.mu.Lock()
		_, draining := m.draining[name]
		m.mu.Unlock()
		if !draining {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tombstone for %s never cleared", name)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitReplacementConn blocks until a NEW conn (distinct from old) has been
// opened for name — i.e. the reclaimer restarted the sender and its owner
// opened the replacement conn.
func waitReplacementConn(t *testing.T, fl *fakeListen, name string, old *fakeConn) *fakeConn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if c := fl.getConn(name); c != nil && c != old {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("replacement conn for %s never opened — the reclaimer "+
				"dropped the deferred restart (#5094)", name)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestReclaimerHealsRestartAfterJoinTimeout_5094 drives the changed-config
// restart path into a JOIN TIMEOUT (old owner wedged in conn.Close), then proves
// that once the wedged owner finally exits the reclaimer STARTS the deferred
// replacement — the interface is not left senderless.
//
// It also asserts the two invariants that must survive the fix: never two live
// conns (the replacement opens only after the old conn is proven closed), and
// Status surfaces the wedged interface as join-timed-out while it is stuck.
//
// RED on revert: against the pre-#5094 delete-only reclaimer no replacement is
// ever started, so waitReplacementConn times out and the test fails.
func TestReclaimerHealsRestartAfterJoinTimeout_5094(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	// Wedge the old sender inside conn.Close so its `stopped` never closes and
	// the restart join TIMES OUT. `reached` fires once the owner is parked.
	wedge := make(chan struct{})
	reached := make(chan struct{})
	var once sync.Once
	old.setBeforeClose(func() {
		once.Do(func() { close(reached) })
		<-wedge
	})

	orig := claimWaitTimeout
	claimWaitTimeout = 100 * time.Millisecond
	defer func() { claimWaitTimeout = orig }()

	// Changed-config Apply (restart): hard-stops the old sender, hits the wedged
	// join, times out, arms the reclaimer, and returns in the degraded state.
	if err := m.Apply([]*config.RAInterfaceConfig{configChanged("lo")}); err != nil {
		t.Fatalf("changed-config Apply: %v", err)
	}
	<-reached // old owner is parked in Close (its conn still live)

	// Degraded window: no active sender, tombstone HELD and flagged
	// join-timed-out, and never >1 live conn (the old is still live).
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if live {
		t.Fatal("a replacement was started while the old conn may be live (≤1-conn violated)")
	}
	if lc := fl.liveCount(); lc != 1 {
		t.Fatalf("live conns during the wedge = %d, want 1", lc)
	}
	if !statusJoinTimedOut(m, "lo") {
		t.Fatal("Status did not surface the wedged interface as join-timed-out (#5094)")
	}

	// Release the wedge; the owner exits and the reclaimer must start the
	// deferred replacement rather than dropping it.
	close(wedge)
	newC := waitReplacementConn(t, fl, "lo", old)
	waitWrites(t, newC, 1)

	m.mu.Lock()
	_, healed := m.senders["lo"]
	m.mu.Unlock()
	if !healed {
		t.Fatal("reclaimer left the interface senderless after the wedged owner " +
			"exited — the deferred restart was dropped (#5094)")
	}
	if lc := fl.liveCount(); lc != 1 {
		t.Fatalf("after heal: live conns = %d, want 1 (old closed, replacement up)", lc)
	}
	for _, info := range m.Status() {
		if info.Interface == "lo" && info.State == "draining" {
			t.Fatalf("tombstone lingered after the reclaim heal: %+v", info)
		}
	}
	_ = m.Clear()
}

// TestReclaimerEmitsOwedGoodbyeAfterJoinTimeout_5094 drives the terminal-goodbye
// half. A hard Clear parks the owner in Close (it reads modeHard and so exits
// WITHOUT emitting a goodbye itself); its join times out and arms the reclaimer.
// A graceful Withdraw then flips goodbyeWanted on the still-held tombstone but
// does NOT own the release (the reclaimer does). Once the wedged owner exits the
// reclaimer must emit the owed standalone goodbye.
//
// RED on revert: against the pre-#5094 delete-only reclaimer the tombstone is
// dropped with no goodbye (the owner never emitted one; Withdraw did not own the
// release), so goodbyeStats stays empty and the test fails.
func TestReclaimerEmitsOwedGoodbyeAfterJoinTimeout_5094(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	// Wedge the old sender in Close; `parked` fires once it is there — i.e. it
	// has already read modeHard and decided NOT to emit a goodbye itself.
	wedge := make(chan struct{})
	parked := make(chan struct{})
	var once sync.Once
	old.setBeforeClose(func() {
		once.Do(func() { close(parked) })
		<-wedge
	})

	orig := claimWaitTimeout
	claimWaitTimeout = 100 * time.Millisecond
	defer func() { claimWaitTimeout = orig }()

	// Hard Clear: installs a tombstone, signalStop(modeHard); its join blocks on
	// the wedged owner, so run it in a goroutine.
	clearDone := make(chan error, 1)
	go func() { clearDone <- m.Clear() }()
	<-parked // owner parked in Close having read modeHard (no self-goodbye)

	// Wait until Clear's join timed out and armed the reclaimer.
	deadline := time.Now().Add(3 * time.Second)
	for !statusJoinTimedOut(m, "lo") {
		if time.Now().After(deadline) {
			t.Fatal("Clear never armed the join-timeout reclaimer")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// A graceful Withdraw flips goodbyeWanted on the still-held tombstone. It
	// does NOT own the release (Clear's reclaimer does), so the owed goodbye is
	// the reclaimer's responsibility once the owner exits.
	_ = m.Withdraw()

	// Release the wedge; the owner exits (modeHard, no goodbye) and the reclaimer
	// must emit the owed standalone goodbye.
	close(wedge)
	<-clearDone
	waitDrainCleared(t, m, "lo")

	total, conns := fl.goodbyeStats("lo")
	if conns != 1 || total == 0 {
		t.Fatalf("reclaimer did not emit the owed goodbye after the join timeout "+
			"(%d conns / %d writes); #5094 must not drop the terminal goodbye", conns, total)
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if live {
		t.Fatal("a replacement was started for a withdrawn interface (the withdraw must win)")
	}
}
