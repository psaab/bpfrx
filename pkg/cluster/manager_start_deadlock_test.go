package cluster

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// deadlockNlHandle is a nlLinkGetter that, on its first LinkByName call,
// reproduces the exact in-flight callback that makes Manager.Start's old lock
// ordering deadlock: it runs on the monitor poll goroutine (the one
// Monitor.Stop joins via wg.Wait), signals the test, waits for the test to
// arrange the race, then calls back into the manager's SetMonitorWeight —
// which takes m.mu. If Manager.Start is holding m.mu across Monitor.Stop, that
// callback blocks forever (AB-BA), so the poll goroutine never exits and
// wg.Wait never returns. See #4828.
type deadlockNlHandle struct {
	mgr     *Manager
	rgID    int
	iface   string
	weight  int
	reached chan struct{} // closed once the poll goroutine is on-CPU in LinkByName
	proceed chan struct{} // closed by the test once Start is (about to be) mid-Stop
	once    sync.Once
}

func (h *deadlockNlHandle) LinkByName(name string) (netlink.Link, error) {
	h.once.Do(func() {
		close(h.reached)
		<-h.proceed
		// Model the poll loop's SetMonitorWeight callback (monitor.go). This
		// acquires m.mu; if Start holds m.mu across Stop() this blocks
		// permanently and the poll goroutine can never exit.
		h.mgr.SetMonitorWeight(h.rgID, h.iface, true, h.weight)
	})
	return nil, fmt.Errorf("deadlockNlHandle: no such link %q (test)", name)
}

func (h *deadlockNlHandle) Close() {}

// TestManagerStartMonitorStopNoDeadlock reproduces the #4828 AB-BA deadlock:
// Manager.Start() must not hold m.mu across the previous monitor's Stop(),
// because the monitor poll goroutine calls SetMonitorWeight (which takes m.mu)
// and Stop() blocks joining that goroutine. Pre-fix this test times out
// (deadlock); post-fix Start() returns promptly.
func TestManagerStartMonitorStopNoDeadlock(t *testing.T) {
	m := NewManager(0, 1)

	// A redundancy group with one interface monitor so the poll loop reaches
	// pollInterfaceMonitors -> nlHandle.LinkByName. Node 0 owns slot-0 names.
	groups := []*config.RedundancyGroup{
		{
			ID: 0,
			InterfaceMonitors: []*config.InterfaceMonitor{
				{Interface: "ge-0/0/0", Weight: 100},
			},
		},
	}

	fake := &deadlockNlHandle{
		mgr:     m,
		rgID:    0,
		iface:   "ge-0/0/0",
		weight:  100,
		reached: make(chan struct{}),
		proceed: make(chan struct{}),
	}

	// Install a monitor with the injected handle directly (white-box) so the
	// existing monitor's poll goroutine is the one whose SetMonitorWeight
	// callback races Start()'s Stop(). Manager.Start() itself creates its own
	// monitor via NewMonitor, so we cannot inject the handle through Start.
	prev := NewMonitor(m, groups)
	prev.nlHandle = fake
	m.mu.Lock()
	m.monitor = prev
	m.mu.Unlock()

	monCtx, monCancel := context.WithCancel(context.Background())
	defer monCancel()
	prev.Start(monCtx)

	// Wait until the poll goroutine is on-CPU inside LinkByName and parked on
	// proceed. It is now guaranteed not to touch m.mu until we release it.
	select {
	case <-fake.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("monitor poll goroutine never reached LinkByName")
	}

	done := make(chan struct{})
	go func() {
		// Pre-fix: acquires m.mu, calls prev.Stop() -> wg.Wait() while still
		// holding m.mu. Post-fix: swaps the pointer, releases m.mu, then Stops.
		m.Start(context.Background())
		close(done)
	}()

	// Give the Start goroutine time to acquire the (uncontended) m.mu and enter
	// prev.Stop(). Nothing else contends m.mu during this window: the poll
	// goroutine is parked on proceed. After this, pre-fix code has Start
	// holding m.mu inside wg.Wait().
	time.Sleep(250 * time.Millisecond)

	// Release the poll goroutine's SetMonitorWeight callback. Pre-fix it now
	// blocks on m.mu (held by Start), so wg.Wait() -> Start() never returns.
	close(fake.proceed)

	select {
	case <-done:
		// Fixed: Start released m.mu before Stop(), so the callback completed,
		// the poll goroutine exited, and Start returned.
	case <-time.After(5 * time.Second):
		t.Fatal("Manager.Start() deadlocked against the monitor poll goroutine (#4828 AB-BA)")
	}

	// The manager should have swapped in a fresh monitor.
	m.mu.RLock()
	cur := m.monitor
	m.mu.RUnlock()
	if cur == nil || cur == prev {
		t.Fatalf("Manager.Start did not install a new monitor: cur=%p prev=%p", cur, prev)
	}

	// Tear down the replacement monitor's goroutine.
	m.Stop()
}
