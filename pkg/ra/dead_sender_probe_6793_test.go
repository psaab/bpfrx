package ra

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// TestHasDeadSendersSeesAFailedAsyncOpen6793 is the probe the #6793 retry owner
// gates on, and it is PAIRED: the same manager, two listen outcomes, opposite
// answers.
//
// A sender's conn open runs ASYNCHRONOUSLY in the owner goroutine (the bind
// retry must not run under m.mu), so `startLocked` returns success and the
// failure surfaces only as `dead()` later. That is why nothing noticed: Apply
// reported success, the interface advertised nothing, and the only state
// recording it was a per-sender flag no caller read.
//
// The success leg is load-bearing. Without it, "HasDeadSenders is true after a
// failed open" is satisfied by an implementation that returns true always,
// which would make the always-on reassert loop re-apply RA every 30s forever.
func TestHasDeadSendersSeesAFailedAsyncOpen6793(t *testing.T) {
	requireLo(t)

	t.Run("open-fails", func(t *testing.T) {
		origListen, origEnsure := listenFn, ensureLinkLocalFn
		t.Cleanup(func() { listenFn, ensureLinkLocalFn = origListen, origEnsure })
		ensureLinkLocalFn = func(*net.Interface) error { return nil }
		listenFn = func(*net.Interface, ndp.Addr) (ndpConn, netip.Addr, error) {
			return nil, netip.Addr{}, errors.New("simulated: no usable link-local yet")
		}

		m := New()
		if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		// The open is async; wait for the sender to settle either way rather
		// than sleeping a fixed interval.
		waitFor(t, "the sender to finish its conn open attempt", func() bool {
			return m.HasDeadSenders()
		})
		if got := m.DeadSenderInterfaces(); len(got) != 1 || got[0] != "lo" {
			t.Fatalf("DeadSenderInterfaces() = %v, want [lo]", got)
		}
	})

	t.Run("open-succeeds", func(t *testing.T) {
		installFakeListen(t)

		m := New()
		if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		waitFor(t, "the sender's conn to come up", func() bool {
			m.mu.Lock()
			s := m.senders["lo"]
			m.mu.Unlock()
			return s != nil && s.waitConnReady(claimWaitTimeout)
		})
		if m.HasDeadSenders() {
			t.Fatal("HasDeadSenders() = true for a sender whose conn opened — " +
				"the always-on #6793 loop would re-apply RA every tick forever, " +
				"restarting healthy senders")
		}
		if got := m.DeadSenderInterfaces(); len(got) != 0 {
			t.Fatalf("DeadSenderInterfaces() = %v, want empty", got)
		}
	})
}

// TestApplyRebuildsADeadSenderOnceItCanOpen6793 is the property the retry owner
// exists to deliver: re-driving Apply with the UNCHANGED desired set must
// rebuild a dead sender. It is the #2865 branch, asserted end to end — that
// branch existed before #6793, but nothing in standalone ever called Apply
// again, so it was unreachable.
//
// The mid-test flip from failing to succeeding listen is the point: a rebuild
// that only worked when the config changed would pass a fixture that changed
// the config, and that is exactly the bug.
func TestApplyRebuildsADeadSenderOnceItCanOpen6793(t *testing.T) {
	requireLo(t)

	origListen, origEnsure := listenFn, ensureLinkLocalFn
	t.Cleanup(func() { listenFn, ensureLinkLocalFn = origListen, origEnsure })
	ensureLinkLocalFn = func(*net.Interface) error { return nil }

	fail := true
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		if fail {
			return nil, netip.Addr{}, errors.New("simulated: link-local not settled")
		}
		return newFakeConn(), netip.MustParseAddr("fe80::1"), nil
	}

	m := New()
	cfgs := []*config.RAInterfaceConfig{testCfg("lo")}
	if err := m.Apply(cfgs); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	waitFor(t, "the first open to fail", func() bool { return m.HasDeadSenders() })

	// The link-local settles. The desired set is BYTE-IDENTICAL — no config
	// change — which is the whole point.
	fail = false
	if err := m.Apply(cfgs); err != nil {
		t.Fatalf("rebuild Apply: %v", err)
	}
	waitFor(t, "the dead sender to be rebuilt", func() bool { return !m.HasDeadSenders() })

	m.mu.Lock()
	s := m.senders["lo"]
	m.mu.Unlock()
	if s == nil {
		t.Fatal("no sender for lo after the rebuild")
	}
	if s.dead() {
		t.Fatal("the sender is still dead after a re-drive with the same config " +
			"— the #2865 rebuild did not run, so the retry owner has nothing to " +
			"drive (#6793)")
	}
}

// waitFor polls cond until true or fails. Polling an OBSERVABLE rather than
// sleeping: the conn open is asynchronous, so a fixed sleep either flakes on a
// loaded machine or hides a rebuild that never happened.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
