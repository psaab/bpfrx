package dhcp

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #1844 gateway-change hook contract (plan §4.3): fires from exactly
// two sites — commitLease on a gateway delta (strictly narrower than
// leaseContentChanged) and finishClient on the real cleanup path of
// every terminal client exit — always outside m.mu.

// hookCounter wires a counting onGatewayChange hook that ALSO calls
// LeaseFor, so any fire site still holding m.mu deadlocks the test
// (the lock-order proof rides every assertion).
func hookCounter(mp **Manager) (*atomic.Int64, func()) {
	var n atomic.Int64
	return &n, func() {
		n.Add(1)
		if m := *mp; m != nil {
			// Re-enter the manager the way the ipmon resolver does
			// (Engine.mu → dhcp.mu). Deadlocks if fired under m.mu.
			_ = m.LeaseFor("ge-0-0-3", AFInet)
		}
	}
}

// TestCommitLeaseGatewayHookMatrix pins the commitLease fire decision:
// first lease fires; content-identical renewal does not; gateway
// change fires; address-only and DNS-only changes do not.
func TestCommitLeaseGatewayHookMatrix(t *testing.T) {
	var m *Manager
	fires, hook := hookCounter(&m)
	m = NewManagerForTestingWithHooks(nil, hook)
	key := clientKey{iface: "ge-0-0-3", family: AFInet}

	prev := v4Lease("10.0.0.5/24")
	if err := m.commitLease(key, prev, nil, nil, nil); err != nil {
		t.Fatalf("initial commitLease: %v", err)
	}
	if got := fires.Load(); got != 1 {
		t.Fatalf("first lease: fires = %d, want 1", got)
	}

	steps := []struct {
		name     string
		next     *Lease
		wantFire bool
	}{
		{"unchanged renewal", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.Obtained = prev.Obtained.Add(30 * time.Minute)
		}), false},
		{"address-only change", v4Lease("10.0.0.99/24"), false},
		{"dns-only change", v4Lease("10.0.0.99/24", func(l *Lease) {
			l.DNS = []netip.Addr{netip.MustParseAddr("10.0.0.54")}
		}), false},
		{"gateway change", v4Lease("10.0.0.99/24", func(l *Lease) {
			l.Gateway = netip.MustParseAddr("10.0.0.254")
		}), true},
	}
	cur := prev
	for _, st := range steps {
		before := fires.Load()
		if err := m.commitLease(key, st.next, cur, nil, nil); err != nil {
			t.Fatalf("%s: commitLease: %v", st.name, err)
		}
		fired := fires.Load() > before
		if fired != st.wantFire {
			t.Fatalf("%s: hook fired = %v, want %v", st.name, fired, st.wantFire)
		}
		disarmRecompile(m)
		cur = st.next
	}
}

// TestFinishClientFiresGatewayHook: every terminal client exit fires
// the hook through finishClient — including exits the run-loop
// ctx.Done branches never see. Modeled with the runClientForTest seam:
// an immediate-return client (the max-retransmission / abort shape)
// and a cancelled blocking client (the Reconcile-removal /
// cancel-mid-exchange shape). Both leave a committed lease behind so
// the record-removal path is exercised, and the hook re-enters
// LeaseFor (deadlock proof).
func TestFinishClientFiresGatewayHook(t *testing.T) {
	t.Run("immediate terminal exit", func(t *testing.T) {
		var m *Manager
		fires, hook := hookCounter(&m)
		committed := make(chan struct{})
		m = NewManagerForTestingWithHooks(func(ctx context.Context, iface string, af AddressFamily) {
			key := clientKey{iface: iface, family: af}
			if err := m.commitLease(key, v4Lease("10.0.0.5/24"), nil, nil, nil); err != nil {
				t.Errorf("commitLease: %v", err)
			}
			close(committed)
			// return = terminal exit (max retransmissions).
		}, hook)
		m.SetDHCPv4Options("ge-0-0-3", nil)
		if !m.Start(context.Background(), "ge-0-0-3", AFInet) {
			t.Fatal("Start refused")
		}
		<-committed
		// commitLease fired once (first lease); finishClient fires
		// once more after removing the record.
		waitFor(t, func() bool { return fires.Load() == 2 })
		if m.LeaseFor("ge-0-0-3", AFInet) != nil {
			t.Fatal("lease record not removed on terminal exit")
		}
	})

	t.Run("cancelled client", func(t *testing.T) {
		var m *Manager
		fires, hook := hookCounter(&m)
		committed := make(chan struct{})
		m = NewManagerForTestingWithHooks(func(ctx context.Context, iface string, af AddressFamily) {
			key := clientKey{iface: iface, family: af}
			if err := m.commitLease(key, v4Lease("10.0.0.5/24"), nil, nil, nil); err != nil {
				t.Errorf("commitLease: %v", err)
			}
			close(committed)
			<-ctx.Done() // block like a real client; exit on cancel
		}, hook)
		m.SetDHCPv4Options("ge-0-0-3", nil)
		if !m.Start(context.Background(), "ge-0-0-3", AFInet) {
			t.Fatal("Start refused")
		}
		<-committed
		// Reconcile to the empty desired set stops the client; it
		// waits on the client's done channel, which closes only AFTER
		// the finishClient defer (lease removal + hook fire) — so the
		// assertions below are deterministic (the withdrawal trigger,
		// plan §4.5).
		m.Reconcile(nil)
		if m.LeaseFor("ge-0-0-3", AFInet) != nil {
			t.Fatal("lease record not removed on client stop")
		}
		if got := fires.Load(); got != 2 {
			t.Fatalf("fires = %d, want 2 (commit + finish)", got)
		}
	})
}

// TestFinishClientSuccessorGuardDoesNotFire: the stale-defer early
// return (registry entry already replaced/removed) changed no lease
// state and must not fire the hook.
func TestFinishClientSuccessorGuardDoesNotFire(t *testing.T) {
	var m *Manager
	fires, hook := hookCounter(&m)
	m = NewManagerForTestingWithHooks(nil, hook)
	m.finishClient(clientKey{iface: "ge-0-0-3", family: AFInet}, &dhcpClient{})
	if got := fires.Load(); got != 0 {
		t.Fatalf("fires = %d, want 0 on successor-guard early return", got)
	}
}

// TestGatewayHookConcurrency drives concurrent commits, terminal
// exits, and reader calls under -race: the hook (which re-enters
// LeaseFor) racing Leases()/LeaseFor snapshots must be clean — the
// plan's bounded-blocking contract (§4.3, Codex r1-3).
func TestGatewayHookConcurrency(t *testing.T) {
	var m *Manager
	_, hook := hookCounter(&m)
	m = NewManagerForTestingWithHooks(func(ctx context.Context, iface string, af AddressFamily) {
		key := clientKey{iface: iface, family: af}
		gw := netip.MustParseAddr("10.0.0.1")
		alt := netip.MustParseAddr("10.0.0.254")
		var prev *Lease
		for i := 0; i < 50; i++ {
			next := v4Lease("10.0.0.5/24", func(l *Lease) {
				if i%2 == 1 {
					l.Gateway = alt
				} else {
					l.Gateway = gw
				}
			})
			if err := m.commitLease(key, next, prev, nil, nil); err != nil {
				t.Errorf("commitLease: %v", err)
				return
			}
			prev = next
		}
		<-ctx.Done()
	}, hook)
	m.SetDHCPv4Options("ge-0-0-3", nil)
	if !m.Start(context.Background(), "ge-0-0-3", AFInet) {
		t.Fatal("Start refused")
	}

	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = m.Leases()
				_ = m.LeaseFor("ge-0-0-3", AFInet)
			}
		}()
	}
	wg.Wait()
	m.Reconcile(nil) // stop the client (fires finishClient hook too)
	disarmRecompile(m)
}

// waitFor polls cond up to ~2s; the client goroutine's defer chain
// (finishClient before close(done)) makes the observed condition
// ordered after the hook fire.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached within deadline")
}
