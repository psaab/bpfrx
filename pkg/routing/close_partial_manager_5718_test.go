package routing

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// closeGuardRuleOps is a do-nothing ruleOps: this test only drives Close, so
// no rule call is expected to run.
type closeGuardRuleOps struct{}

func (closeGuardRuleOps) RuleAdd(*netlink.Rule) error { return nil }
func (closeGuardRuleOps) RuleDel(*netlink.Rule) error { return nil }
func (closeGuardRuleOps) RuleList(int) ([]netlink.Rule, error) {
	return nil, nil
}

// closeGuardRouteLister is a do-nothing routeLister, same rationale.
type closeGuardRouteLister struct{}

func (closeGuardRouteLister) RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	return nil, nil
}
func (closeGuardRouteLister) RouteList(netlink.Link, int) ([]netlink.Route, error) { return nil, nil }
func (closeGuardRouteLister) LinkByIndex(int) (netlink.Link, error)                { return nil, nil }
func (closeGuardRouteLister) LinkByName(string) (netlink.Link, error)              { return nil, nil }

// installLiveKeepalive wires a REAL running keepalive goroutine into the
// tunnel domain and returns its done channel plus a tick counter.
//
// The goroutine has the shape stopAllKeepalivesLocked depends on: it exits on
// ctx.Done and closes `done` on the way out, so `<-runner.done` returning is
// proof the goroutine actually left — not merely that cancel() was called.
func installLiveKeepalive(t *testing.T, m *Manager, name string) (done <-chan struct{}, ticks *atomic.Int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	var counter atomic.Int64

	go func() {
		defer close(doneCh)
		tk := time.NewTicker(200 * time.Microsecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				counter.Add(1)
			}
		}
	}()
	// If the test fails before Close runs, do not leak the goroutine.
	t.Cleanup(cancel)

	m.tunnel.mu.Lock()
	if m.tunnel.keepalives == nil {
		m.tunnel.keepalives = make(map[string]*keepaliveRunner)
	}
	m.tunnel.keepalives[name] = &keepaliveRunner{
		cancel: cancel,
		done:   doneCh,
		state:  &KeepaliveState{RemoteAddr: "198.51.100.1", Interval: 1, MaxRetries: 3},
	}
	m.tunnel.mu.Unlock()

	// Prove it is genuinely running before Close is asked to stop it, so the
	// post-Close assertion is not satisfied by a goroutine that never started.
	deadline := time.Now().Add(2 * time.Second)
	for counter.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("setup: the keepalive goroutine never ran")
		}
		time.Sleep(time.Millisecond)
	}
	return doneCh, &counter
}

// TestCloseReleasesLiveHandleAndKeepalives_5718 is the positive half of the
// #5718 A7-b02-C01 guard: Close must actually do its two jobs on a FULLY wired
// Manager, so the nil guard added for the partial constructors cannot degrade
// it into a no-op.
//
// Both obligations are observed on live state rather than inferred from a nil
// error:
//
//   - the keepalive runner is drained. `<-runner.done` unblocking means the
//     goroutine returned; a Close that skipped stopAll leaves `done` open.
//   - the netlink handle is closed. netlink.Handle.Close() closes each socket
//     and nils the map, so GetSocketReceiveBufferSize reports one entry per
//     live socket before and none after. (A post-close LinkList is NOT an
//     observable — the library silently falls back to a package-level socket.)
//
// #848 is the reason the order matters: stopAll drains BEFORE the handle
// closes, so no in-flight keepalive tick can use-after-close it.
func TestCloseReleasesLiveHandleAndKeepalives_5718(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Skipf("netlink handle unavailable in this environment: %v", err)
	}
	if m.nlHandle == nil {
		t.Fatal("setup: New() must own a netlink handle")
	}
	if m.tunnel == nil {
		t.Fatal("setup: New() must wire the tunnel domain")
	}

	socketsBefore, err := m.nlHandle.GetSocketReceiveBufferSize()
	if err != nil {
		t.Fatalf("setup: reading the handle's sockets: %v", err)
	}
	if len(socketsBefore) == 0 {
		t.Fatal("setup: the handle must own at least one live socket before Close")
	}

	done, ticks := installLiveKeepalive(t, m, "gr-close-5718")

	if err := m.Close(); err != nil {
		t.Fatalf("Close on a fully wired Manager: %v", err)
	}

	// 1) The keepalive goroutine is gone. Close blocks on `<-runner.done`, so
	//    by the time it returns this channel is closed — unless Close skipped
	//    the drain entirely.
	select {
	case <-done:
	default:
		t.Fatalf("Close returned without draining the keepalive runner (goroutine still "+
			"running after %d ticks). stopAll must cancel it AND wait for it to exit "+
			"before the netlink handle is closed, or an in-flight tick uses the closed "+
			"handle (#848)", ticks.Load())
	}

	// 2) The runner is removed from the map, not left as a cancelled corpse
	//    that GetKeepaliveState would still report.
	m.tunnel.mu.Lock()
	remaining := len(m.tunnel.keepalives)
	m.tunnel.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Close left %d keepalive runner(s) registered", remaining)
	}

	// 3) The netlink handle's sockets are released.
	socketsAfter, err := m.nlHandle.GetSocketReceiveBufferSize()
	if err != nil {
		t.Fatalf("reading the handle's sockets after Close: %v", err)
	}
	if len(socketsAfter) != 0 {
		t.Fatalf("Close left %d of %d netlink socket(s) open: the Manager is the sole "+
			"owner of the handle and must release it", len(socketsAfter), len(socketsBefore))
	}
}

// TestClosePartialTestManagersDoesNotPanic_5718 is the #5718 A7-b02-C01
// fail-on-revert.
//
// The partial test-manager constructors in test_seams.go wire only the domains
// their callers exercise and leave the rest nil. Their doc comments told
// callers that Close nil-guards the unwired state, but Close guarded only
// nlHandle and called m.tunnel.stopAll() unconditionally. stopAll immediately
// takes t.mu (tunnel_keepalive_runner.go), which dereferences the nil
// *tunnelManager, so the documented `defer m.Close()` panicked the caller's
// test rather than cleaning up.
//
// A constructor this package exports must produce a Manager that is safe to
// Close, so this test drives Close on every partial constructor. The
// fully-wired case is covered above, where the guard is proven not to have
// turned Close into a no-op.
func TestClosePartialTestManagersDoesNotPanic_5718(t *testing.T) {
	t.Run("rule ops manager", func(t *testing.T) {
		m := NewManagerWithRuleOpsForTest(closeGuardRuleOps{})
		if m.tunnel != nil {
			t.Fatal("setup: NewManagerWithRuleOpsForTest is expected to leave the " +
				"tunnel domain nil — that unwired domain is what Close must guard")
		}
		if m.nlHandle != nil {
			t.Fatal("setup: NewManagerWithRuleOpsForTest is expected to leave nlHandle nil")
		}
		// Panics with a nil-pointer dereference in tunnelManager.stopAll
		// without the Close guard.
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a rule-ops test manager: %v", err)
		}
	})

	t.Run("route lister manager", func(t *testing.T) {
		m := NewManagerWithRouteListerForTest(closeGuardRouteLister{})
		if m.tunnel != nil {
			t.Fatal("setup: NewManagerWithRouteListerForTest is expected to leave " +
				"the tunnel domain nil")
		}
		if m.nlHandle != nil {
			t.Fatal("setup: NewManagerWithRouteListerForTest is expected to leave nlHandle nil")
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a route-lister test manager: %v", err)
		}
	})

	t.Run("link ops manager still drains keepalives", func(t *testing.T) {
		// The link-ops constructor DOES populate tunnel, so the guard must not
		// turn Close into a no-op there: a live runner must still be cancelled
		// and drained (#848), on a Manager that has no netlink handle at all.
		m := NewManagerWithLinkOpsForTest(nil)
		if m.tunnel == nil {
			t.Fatal("setup: NewManagerWithLinkOpsForTest must wire the tunnel domain")
		}
		done, ticks := installLiveKeepalive(t, m, "gr-linkops-5718")

		if err := m.Close(); err != nil {
			t.Fatalf("Close on a link-ops test manager: %v", err)
		}
		select {
		case <-done:
		default:
			t.Fatalf("Close on a tunnel-wired partial Manager must still drain the "+
				"keepalive runner; the goroutine is still running after %d ticks",
				ticks.Load())
		}
		m.tunnel.mu.Lock()
		remaining := len(m.tunnel.keepalives)
		m.tunnel.mu.Unlock()
		if remaining != 0 {
			t.Fatalf("Close left %d keepalive runner(s) registered", remaining)
		}
	})
}
