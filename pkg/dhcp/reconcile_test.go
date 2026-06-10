package dhcp

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeRunner stands in for the per-client run goroutine: it records
// every start and blocks until cancellation (terminal=false) or exits
// immediately (terminal=true).
type fakeRunner struct {
	mu       sync.Mutex
	starts   map[string]int
	terminal bool
}

func newFakeRunner(terminal bool) *fakeRunner {
	return &fakeRunner{starts: make(map[string]int), terminal: terminal}
}

func runnerKey(iface string, af AddressFamily) string {
	return fmt.Sprintf("%s/%d", iface, af)
}

func (f *fakeRunner) run(ctx context.Context, iface string, af AddressFamily) {
	f.mu.Lock()
	f.starts[runnerKey(iface, af)]++
	f.mu.Unlock()
	if f.terminal {
		return
	}
	<-ctx.Done()
}

func (f *fakeRunner) startCount(iface string, af AddressFamily) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts[runnerKey(iface, af)]
}

// waitStartCount polls until the runner has seen at least want starts
// for the key (start counting happens inside the client goroutine, so
// it lags Start's synchronous registration), then asserts exactness.
func waitStartCount(t *testing.T, fr *fakeRunner, iface string, af AddressFamily, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for fr.startCount(iface, af) < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := fr.startCount(iface, af); got != want {
		t.Fatalf("starts(%s/%d) = %d, want %d", iface, af, got, want)
	}
}

func waitForRunning(t *testing.T, m *Manager, want int) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h := m.RunningClientHandlesForTesting()
		if len(h) == want {
			return h
		}
		if time.Now().After(deadline) {
			t.Fatalf("running clients = %d, want %d (handles: %v)",
				len(h), want, h)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReconcileStartsNewClients(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)
	defer m.StopAll()

	m.Reconcile([]ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet},
		{Iface: "ge-0-0-3", Family: AFInet6, V6: &DHCPv6Options{Stateless: true}},
	})

	waitForRunning(t, m, 2)
	waitStartCount(t, fr, "ge-0-0-3", AFInet, 1)
	waitStartCount(t, fr, "ge-0-0-3", AFInet6, 1)
}

func TestReconcileStopsRemovedClients(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)
	defer m.StopAll()

	specs := []ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet, V4: &DHCPv4Options{LeaseTime: 300}},
		{Iface: "fxp0", Family: AFInet},
	}
	m.Reconcile(specs)
	waitForRunning(t, m, 2)

	// Seed lease state for the client about to be removed so the stop
	// path's lease/address cleanup is exercised (nil netlink handle is
	// guarded in removeAddress).
	m.SeedLeaseForTesting("ge-0-0-3", AFInet, &Lease{
		Interface: "ge-0-0-3",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("10.0.0.5/24"),
	})

	// Drop ge-0-0-3 from config; fxp0 stays.
	m.Reconcile(specs[1:])

	handles := waitForRunning(t, m, 1)
	if _, ok := handles["fxp0/4"]; !ok {
		t.Fatalf("fxp0 client missing after reconcile: %v", handles)
	}
	waitStartCount(t, fr, "fxp0", AFInet, 1)
	if l := m.LeaseFor("ge-0-0-3", AFInet); l != nil {
		t.Errorf("lease record for stopped client not cleared: %+v", l)
	}
	m.mu.Lock()
	_, optsLeft := m.v4opts["ge-0-0-3"]
	m.mu.Unlock()
	if optsLeft {
		t.Error("v4opts for removed client not cleared")
	}
}

func TestReconcileOptionChangeRestartsClient(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)
	defer m.StopAll()

	m.Reconcile([]ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet6,
			V6: &DHCPv6Options{Stateless: false, IATypes: []string{"ia-na"}}},
	})
	before := waitForRunning(t, m, 1)

	// Same (iface, family), changed option identity: stateless flip.
	// Stateless is captured at run-goroutine start, so this MUST
	// restart the client (#1793 / plan §5.4 item 1).
	m.Reconcile([]ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet6,
			V6: &DHCPv6Options{Stateless: true}},
	})
	after := waitForRunning(t, m, 1)

	waitStartCount(t, fr, "ge-0-0-3", AFInet6, 2)
	if before["ge-0-0-3/6"] == after["ge-0-0-3/6"] {
		t.Fatal("client handle unchanged — option change did not restart client")
	}
}

func TestReconcileDUIDTypeChangeRestartsClient(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)
	defer m.StopAll()

	m.Reconcile([]ClientSpec{{Iface: "ge-0-0-3", Family: AFInet6}})
	waitForRunning(t, m, 1)

	m.Reconcile([]ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet6, DUIDType: "duid-llt"},
	})
	waitForRunning(t, m, 1)
	waitStartCount(t, fr, "ge-0-0-3", AFInet6, 2)
}

// TestReconcileLeaseChangeDoesNotRestart is the no-restart-on-lease-change
// invariant (AGY r3, plan §5.4 item 3): lease changes fire the
// onAddressChange callback, which re-enters applyConfig and thus
// Reconcile. If the diff keyed on lease/address state, every lease event
// would restart the client and loop forever. A reconcile with an
// unchanged config but changed lease state MUST be a no-op.
func TestReconcileLeaseChangeDoesNotRestart(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)
	defer m.StopAll()

	specs := []ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet, V4: &DHCPv4Options{LeaseTime: 300}},
		{Iface: "ge-0-0-3", Family: AFInet6,
			V6: &DHCPv6Options{IATypes: []string{"ia-na", "ia-pd"}}},
	}
	m.Reconcile(specs)
	before := waitForRunning(t, m, 2)

	// Simulate a lease change (what the real run goroutine does when a
	// DORA/solicit completes or a renewal moves the address).
	m.SeedLeaseForTesting("ge-0-0-3", AFInet, &Lease{
		Interface: "ge-0-0-3",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("10.0.0.5/24"),
		Obtained:  time.Now(),
	})
	m.Reconcile(specs)

	// And again with a different address — still no restart.
	m.SeedLeaseForTesting("ge-0-0-3", AFInet, &Lease{
		Interface: "ge-0-0-3",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("10.0.0.99/24"),
		Obtained:  time.Now(),
	})
	m.Reconcile(specs)

	after := waitForRunning(t, m, 2)
	for k := range before {
		if before[k] != after[k] {
			t.Errorf("client %s restarted on lease-only change", k)
		}
	}
	waitStartCount(t, fr, "ge-0-0-3", AFInet, 1)
	waitStartCount(t, fr, "ge-0-0-3", AFInet6, 1)
}

// TestTerminalExitDeregistersAndAllowsRestart covers #1793 defect 3:
// a run goroutine that exits terminally (DHCPv4 max retransmissions,
// DHCPv6 link-local abort) must deregister itself so a later Start for
// the same key is not a permanent no-op.
func TestTerminalExitDeregistersAndAllowsRestart(t *testing.T) {
	fr := newFakeRunner(true) // exits immediately = terminal failure
	m := NewManagerForTesting(fr.run)

	m.Start(context.Background(), "ge-0-0-3", AFInet)
	waitForRunning(t, m, 0) // terminal exit must clear the registry

	// A subsequent Start must actually start a new client.
	m.Start(context.Background(), "ge-0-0-3", AFInet)
	deadline := time.Now().Add(5 * time.Second)
	for fr.startCount("ge-0-0-3", AFInet) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("starts = %d, want 2 — Start blocked by stale registry entry",
				fr.startCount("ge-0-0-3", AFInet))
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitForRunning(t, m, 0)
}

func TestStopAllClearsRegistry(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)

	m.Reconcile([]ClientSpec{
		{Iface: "ge-0-0-3", Family: AFInet},
		{Iface: "fxp0", Family: AFInet6},
	})
	waitForRunning(t, m, 2)

	m.StopAll()
	if h := m.RunningClientHandlesForTesting(); len(h) != 0 {
		t.Fatalf("registry not cleared after StopAll: %v", h)
	}

	// Registry hygiene: a fresh Start after StopAll must work.
	m.Start(context.Background(), "ge-0-0-3", AFInet)
	waitForRunning(t, m, 1)
	m.StopAll()
}

func TestReconcileEmptyStopsEverything(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)

	m.Reconcile([]ClientSpec{{Iface: "ge-0-0-3", Family: AFInet}})
	waitForRunning(t, m, 1)

	m.Reconcile(nil)
	if h := m.RunningClientHandlesForTesting(); len(h) != 0 {
		t.Fatalf("clients still running after empty reconcile: %v", h)
	}
}

// TestRenewDoesNotResurrectRemovedClient pins the Renew-vs-Reconcile
// removal race (Codex review on PR #1815): Renew is reachable from
// gRPC outside applySem, so it can capture a client pointer, cancel
// it, and block on done while a concurrent Reconcile removes the key
// from config. Renew must then NOT restart the client — restarting
// would resurrect a client the operator just deconfigured.
//
// Interleaving is made deterministic by a run func that signals when
// cancellation reached it and then holds the client "running" (done
// not yet closed) until released, freezing Renew inside its wait
// window while Reconcile([]) deletes the option state.
func TestRenewDoesNotResurrectRemovedClient(t *testing.T) {
	fr := newFakeRunner(false)
	cancelled := make(chan struct{})
	release := make(chan struct{})
	m := NewManagerForTesting(func(ctx context.Context, iface string, af AddressFamily) {
		fr.run(ctx, iface, af) // records the start, returns on ctx.Done()
		close(cancelled)
		<-release // hold done open so Renew stays in its wait window
	})

	m.Reconcile([]ClientSpec{{Iface: "fxp0", Family: AFInet}})
	waitForRunning(t, m, 1)

	errCh := make(chan error, 1)
	go func() { errCh <- m.Renew("fxp0") }()

	// Renew has captured dc and cancelled it; it is now blocked on
	// dc.done, which stays open until release closes.
	<-cancelled

	// Concurrent removal: Reconcile deletes the option state under
	// m.mu synchronously in its first section, then blocks on the
	// same done channel in its stop loop.
	recDone := make(chan struct{})
	go func() { m.Reconcile(nil); close(recDone) }()
	deadline := time.Now().Add(5 * time.Second)
	for m.HasOptionStateForTesting("fxp0", AFInet) {
		if time.Now().After(deadline) {
			t.Fatal("Reconcile(nil) never removed option state")
		}
		time.Sleep(2 * time.Millisecond)
	}

	close(release)
	<-recDone
	if err := <-errCh; err == nil {
		t.Fatal("Renew should report failure when the client was removed from config mid-renew")
	}

	// The client must NOT have been restarted: exactly the original
	// start, and an empty registry.
	if got := fr.startCount("fxp0", AFInet); got != 1 {
		t.Fatalf("starts = %d, want 1 (no resurrection)", got)
	}
	time.Sleep(50 * time.Millisecond)
	if h := m.RunningClientHandlesForTesting(); len(h) != 0 {
		t.Fatalf("running clients = %v, want none", h)
	}
}

// TestReconcilePrunesOptionStateForDeregisteredClients pins the
// round-4 interleaving from the Codex review on PR #1815: by the time
// a removal Reconcile runs, the renewing client may already be
// deregistered (Renew cancelled it and finishClient deleted the
// registry entry), so the registered-clients loop never visits the
// key. Reconcile must still prune the option-state entry — Renew's
// membership guard reads it as the desired-config signal, and a stale
// entry would let Renew resurrect the removed client.
func TestReconcilePrunesOptionStateForDeregisteredClients(t *testing.T) {
	fr := newFakeRunner(false)
	m := NewManagerForTesting(fr.run)

	m.Reconcile([]ClientSpec{
		{Iface: "fxp0", Family: AFInet},
		{Iface: "fxp0", Family: AFInet6, V6: &DHCPv6Options{Stateless: true}},
	})
	waitForRunning(t, m, 2)

	// Deregister both clients without a Reconcile (models the
	// mid-Renew window where finishClient already ran): cancel and
	// wait for done via StopAll, which leaves option state behind.
	m.StopAll()
	waitForRunning(t, m, 0)
	if !m.HasOptionStateForTesting("fxp0", AFInet) ||
		!m.HasOptionStateForTesting("fxp0", AFInet6) {
		t.Fatal("precondition: option state should survive StopAll")
	}

	// Removal Reconcile with no registered clients must still prune.
	m.Reconcile(nil)
	if m.HasOptionStateForTesting("fxp0", AFInet) {
		t.Fatal("v4 option state not pruned for deregistered client")
	}
	if m.HasOptionStateForTesting("fxp0", AFInet6) {
		t.Fatal("v6 option state not pruned for deregistered client")
	}

	// And the Renew guard therefore cannot restart: no client, no
	// membership — Renew reports an error and starts nothing.
	if err := m.Renew("fxp0"); err == nil {
		t.Fatal("Renew should fail after removal")
	}
	if got := fr.startCount("fxp0", AFInet); got != 1 {
		t.Fatalf("v4 starts = %d, want 1 (no resurrection)", got)
	}
}
